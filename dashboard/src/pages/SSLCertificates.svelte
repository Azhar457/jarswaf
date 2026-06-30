<script lang="ts">
  import { onMount } from "svelte";
  import { Lock, RefreshCw, ShieldCheck, AlertTriangle } from "lucide-svelte";
  import { toast } from "../lib/toast";
  import Card from "../components/ui/Card.svelte";
  import Badge from "../components/ui/Badge.svelte";
  import DataTable from "../components/ui/DataTable.svelte";
  import Button from "../components/ui/Button.svelte";
  import ConfirmationModal from "../components/ui/ConfirmationModal.svelte";
  import AddCertificateModal from "../components/ui/AddCertificateModal.svelte";

  interface SslCert {
    domain: string;
    issuer: string;
    valid_from: string;
    valid_until: string;
    status: string;
    auto_renew: boolean;
  }

  let certs: SslCert[] = [];
  let loading = true;

  let showAddModal = false;
  let addModalRef: AddCertificateModal;

  let showRevokeModal = false;
  let certToRevoke: string | null = null;
  let renewingDomains: Record<string, boolean> = {};

  async function fetchCerts() {
    try {
      loading = true;
      const res = await fetch("http://localhost:8080/api/v1/ssl/certificates");
      if (res.ok) {
        certs = await res.json();
      }
    } catch (e) {
      console.error("Failed to fetch SSL certificates:", e);
      toast.error("Failed to load certificates from backend.");
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    fetchCerts();
  });

  async function forceRenew(domain: string) {
    renewingDomains[domain] = true;
    toast.info(`Initiating ACME renewal for ${domain}...`);

    try {
      const res = await fetch("http://localhost:8080/api/v1/ssl/renew", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });

      const data = await res.json();
      if (res.ok) {
        toast.success(data.message || `Successfully requested renewal for ${domain}`);
        // Optionally refetch certificates after a delay
        setTimeout(fetchCerts, 3000);
      } else {
        toast.error(`Renewal failed: ${data.message || "Unknown error"}`);
      }
    } catch (e) {
      console.error(e);
      toast.error(`Error connecting to ACME service for ${domain}.`);
    } finally {
      renewingDomains[domain] = false;
    }
  }

  function confirmRevoke(domain: string) {
    certToRevoke = domain;
    showRevokeModal = true;
  }

  async function submitNewCert(
    event: CustomEvent<{ domain: string; provider: string; email: string }>,
  ) {
    try {
      const res = await fetch("http://localhost:8080/api/v1/ssl/certificates", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(event.detail),
      });

      const data = await res.json();
      if (res.ok) {
        toast.success(
          `Successfully requested Let's Encrypt certificate for ${event.detail.domain}`,
        );
        showAddModal = false;
        fetchCerts();
      } else {
        toast.error(`Request failed: ${data.error || "Unknown error"}`);
        if (addModalRef) addModalRef.resetLoading();
      }
    } catch (e) {
      console.error(e);
      toast.error(`Error communicating with backend.`);
      if (addModalRef) addModalRef.resetLoading();
    }
  }

  async function executeRevoke() {
    if (!certToRevoke) return;

    try {
      const res = await fetch(`http://localhost:8080/api/v1/ssl/certificates/${certToRevoke}`, {
        method: "DELETE",
      });

      const data = await res.json();
      if (res.ok) {
        toast.success(`Certificate for ${certToRevoke} revoked and deleted.`);
        fetchCerts();
      } else {
        toast.error(`Revoke failed: ${data.error || "Unknown error"}`);
      }
    } catch (e) {
      console.error(e);
      toast.error(`Error deleting certificate.`);
    } finally {
      showRevokeModal = false;
      certToRevoke = null;
    }
  }

  function getDaysLeft(dateString: string): number {
    const expires = new Date(dateString).getTime();
    const now = new Date().getTime();
    const diff = expires - now;
    return Math.ceil(diff / (1000 * 3600 * 24));
  }
</script>

<div class="space-y-6 max-h-full overflow-y-auto pr-1">
  <div class="flex justify-between items-center gap-4">
    <div>
      <h1 class="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2 md:text-3xl">
        <Lock class="text-blue-500" /> SSL Certificates (ACME)
      </h1>
      <p class="text-text-secondary text-sm mt-1">
        Manage TLS/SSL certificates and automatic Let's Encrypt renewals for your Virtual Hosts.
      </p>
    </div>
    <Button
      variant="primary"
      on:click={() => (showAddModal = true)}
      className="shrink-0"
    >
      Add SSL Certificate
    </Button>
  </div>

  <Card className="p-0 overflow-hidden">
    <DataTable columns={["Domain", "Issuer", "Expiry Date", "Status", "Actions"]}>
      {#if loading}
        <tr>
          <td colspan="5" class="px-6 py-12 text-center text-text-muted">
            <div class="flex items-center justify-center gap-2">
              <RefreshCw class="animate-spin text-accent-blue" size={16} />
              <span>Loading active certificates...</span>
            </div>
          </td>
        </tr>
      {:else if certs.length === 0}
        <tr>
          <td colspan="5" class="px-6 py-12 text-center text-text-muted italic select-none">
            No active ACME certificates found.
          </td>
        </tr>
      {:else}
        {#each certs as cert}
          <tr class="hover:bg-slate-900/20 border-b border-border-muted/40 last:border-0 transition-colors">
            <td class="px-6 py-4 whitespace-nowrap text-text-primary font-bold">{cert.domain}</td>
            <td class="px-6 py-4 whitespace-nowrap text-text-secondary text-sm">{cert.issuer}</td>
            <td class="px-6 py-4 whitespace-nowrap text-text-secondary text-sm font-mono">
              {new Date(cert.valid_until).toLocaleDateString()}
              <span class="text-text-muted ml-1.5 text-xs font-semibold">
                ({getDaysLeft(cert.valid_until)} days left)
              </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
              {#if cert.status === "Active"}
                <Badge variant="success" className="flex items-center gap-1.5"
                  ><ShieldCheck size={12} /> <span>{cert.status}</span></Badge
                >
              {:else}
                <Badge variant="warning" className="flex items-center gap-1.5"
                  ><AlertTriangle size={12} /> <span>{cert.status}</span></Badge
                >
              {/if}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-right">
              <div class="flex justify-end gap-2">
                <Button
                  variant="ghost"
                  disabled={renewingDomains[cert.domain]}
                  on:click={() => forceRenew(cert.domain)}
                  className="text-xs py-1 px-3 flex items-center gap-1.5"
                >
                  <RefreshCw size={12} class={renewingDomains[cert.domain] ? "animate-spin" : ""} />
                  <span>Renew</span>
                </Button>
                <Button
                  variant="danger"
                  on:click={() => confirmRevoke(cert.domain)}
                  className="text-xs py-1 px-3"
                >
                  Revoke
                </Button>
              </div>
            </td>
          </tr>
        {/each}
      {/if}
    </DataTable>
  </Card>
</div>

<ConfirmationModal
  show={showRevokeModal}
  title="Revoke Certificate"
  message="Are you sure you want to revoke and delete this SSL Certificate? HTTPS traffic to this domain will fail immediately."
  confirmText="Revoke"
  on:confirm={executeRevoke}
  on:cancel={() => {
    showRevokeModal = false;
    certToRevoke = null;
  }}
/>

<AddCertificateModal bind:this={addModalRef} bind:show={showAddModal} on:submit={submitNewCert} />
