<script lang="ts">
  import { onMount } from 'svelte';
  import { Lock, RefreshCw, ShieldCheck, AlertTriangle } from 'lucide-svelte';
  import { toast } from '../lib/toast';
  import Card from '../components/ui/Card.svelte';
  import Badge from '../components/ui/Badge.svelte';
  import DataTable from '../components/ui/DataTable.svelte';
  import ConfirmationModal from '../components/ui/ConfirmationModal.svelte';
  import AddCertificateModal from '../components/ui/AddCertificateModal.svelte';

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
        body: JSON.stringify({ domain })
      });
      
      const data = await res.json();
      if (res.ok) {
        toast.success(data.message || `Successfully requested renewal for ${domain}`);
        // Optionally refetch certificates after a delay
        setTimeout(fetchCerts, 3000);
      } else {
        toast.error(`Renewal failed: ${data.message || 'Unknown error'}`);
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

  async function submitNewCert(event: CustomEvent<{domain: string, provider: string, email: string}>) {
    try {
      const res = await fetch("http://localhost:8080/api/v1/ssl/certificates", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(event.detail)
      });
      
      const data = await res.json();
      if (res.ok) {
        toast.success(`Successfully requested Let's Encrypt certificate for ${event.detail.domain}`);
        showAddModal = false;
        fetchCerts();
      } else {
        toast.error(`Request failed: ${data.error || 'Unknown error'}`);
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
        method: "DELETE"
      });
      
      const data = await res.json();
      if (res.ok) {
        toast.success(`Certificate for ${certToRevoke} revoked and deleted.`);
        fetchCerts();
      } else {
        toast.error(`Revoke failed: ${data.error || 'Unknown error'}`);
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

<div class="space-y-6">
  <div class="flex items-start justify-between">
    <div>
      <h1 class="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
        <Lock class="text-blue-500" /> SSL Certificates (ACME Integration)
      </h1>
      <p class="text-slate-400 mt-1">Manage TLS/SSL certificates and automatic Let's Encrypt renewals for your Virtual Hosts.</p>
    </div>
    <button 
      on:click={() => showAddModal = true}
      class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors shadow-[0_0_15px_rgba(37,99,235,0.3)]"
    >
      Add SSL Certificate
    </button>
  </div>

  <Card className="p-0 overflow-hidden border-slate-800">
    <DataTable columns={['Domain', 'Issuer', 'Expiry Date', 'Status', 'Actions']}>
      {#if loading}
        <tr><td colspan="5" class="px-6 py-8 text-center text-slate-500">Loading active certificates...</td></tr>
      {:else if certs.length === 0}
        <tr><td colspan="5" class="px-6 py-8 text-center text-slate-500">No active ACME certificates found.</td></tr>
      {:else}
        {#each certs as cert}
          <tr class="hover:bg-slate-700/30 transition-colors">
            <td class="px-6 py-4 whitespace-nowrap text-slate-200 font-bold">{cert.domain}</td>
            <td class="px-6 py-4 whitespace-nowrap text-slate-400 text-sm">{cert.issuer}</td>
            <td class="px-6 py-4 whitespace-nowrap text-slate-400 text-sm font-mono">
              {new Date(cert.valid_until).toLocaleDateString()} 
              <span class="text-slate-500 ml-1">
                ({getDaysLeft(cert.valid_until)} days)
              </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
              {#if cert.status === 'Active'}
                <Badge variant="success" className="flex items-center gap-1"><ShieldCheck size={12}/> {cert.status}</Badge>
              {:else}
                <Badge variant="warning" className="flex items-center gap-1"><AlertTriangle size={12}/> {cert.status}</Badge>
              {/if}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-right">
              <div class="flex justify-end gap-3">
                <button 
                  on:click={() => forceRenew(cert.domain)} 
                  disabled={renewingDomains[cert.domain]}
                  class="text-xs font-bold text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors disabled:opacity-50"
                >
                  <RefreshCw size={14} class={renewingDomains[cert.domain] ? 'animate-spin' : ''} /> Renew
                </button>
                <button 
                  on:click={() => confirmRevoke(cert.domain)} 
                  class="text-xs font-bold text-red-500 hover:text-red-400 transition-colors"
                >
                  Revoke
                </button>
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
  on:cancel={() => { showRevokeModal = false; certToRevoke = null; }}
/>

<AddCertificateModal 
  bind:this={addModalRef}
  bind:show={showAddModal} 
  on:submit={submitNewCert}
/>
