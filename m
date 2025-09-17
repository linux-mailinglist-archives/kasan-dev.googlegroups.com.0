Return-Path: <kasan-dev+bncBDXYDPH3S4OBBUOWVHDAMGQEKW65RRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A57CB7CEA5
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:13:49 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3eaed4aea75sf2533861f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:13:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758111229; cv=pass;
        d=google.com; s=arc-20240605;
        b=Itjmt0jrl18AH5FD7nZjnu5M5cug/o+bR1IELtY5ivYqGgcdsS2tNowo8zYzUtFFiS
         dNZtRUYZa9Fe8iDFMRJ3fUVvNczTdkVXEpdh21A236APNO/CpG0kzLcwWX/qBQ7GRIEF
         P0YsdCeN7IelgqBakzrVrApC4jMicnEyJkhAAMDk3F2X7UEHxI+inom+ICeGDFjqm38w
         XyXKFqdSJcmWWGE1m5MxfxuS7wpuI+bOfUlVN9sh+GW8MkR1Q2CIkT3M53XtK95FpwL/
         8S7MgpHR+3LTf70pgBA2ZjlW/zvCBZfpm9kt+rinjl2N4mM4pwNugnnNQBH2Sc9VA7YX
         IlkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=e94Towh7kTrjAgzNQKvUvLh2VDpa/hLLt7P0h/8NBOw=;
        fh=k9cAKjCiKkaGEtO9UiQTrjhOxOai+HdbceEb45b9QEA=;
        b=dkfA7h0LI+lK1lWkLY8FBiM2gZxtJxO772IWR0Jgdvh3HmiS8GcHfMk5JQJEansQTU
         lhX9JWP3wRdzYVE+rgTykzHpnwXTyTk2TB2zFiY86PlNii6qNv2Dh/RO0bstZY2R5SEY
         KsKbIt/3C+a8gF0Ye2hZPWykjtlL00NZVLVappAvzlSZ9x1bh8KAINaNN8KUULgN+Dxf
         Amv124Q1znxNDnef4ONTtSUgn2OJgLIrXGgPaJDeVE+UyLjMNK0TPDF3W9XuA9WoQfOR
         MkS8MDvBSfy8sJP5y/ZU3f8gpNmTeYCVNXoGkU3Je7tM5oURZdhDR5VcCrgcew98VnGT
         SGxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LnEjgxL2;
       dkim=neutral (no key) header.i=@suse.cz header.b=UufgrTS2;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LnEjgxL2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=UufgrTS2;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758111229; x=1758716029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=e94Towh7kTrjAgzNQKvUvLh2VDpa/hLLt7P0h/8NBOw=;
        b=kAZncsKBMtXvcDKbwFZHtcDpgdK47qG1qn+DWeibznwW91wS7E2wU6hxHCQyGnXSlT
         R9Y13+VBq2fuYrGrKDFI5qk0b4sV9ZIQuO2GBgyCBJJTtQ7GnMxCgqEztLkSv27iH7oq
         r4nl3wE3Ay5fCzaeNYTmtUOtbvZEIkVXlEBgZap20QRHC/dBki3C8x7qrBIPDIydgj2t
         gH9vZex/bUs1T758wqbeFiqZfNuj++BEZagXXCLmc4Pi3r7SqTT6PPajxw5g2W6X1jWw
         GPyyru0FYEGu1qaHHo2ivSXqWPmidPsOwi/+QHMjQWHXjo6EYNpoHCjEhZ1bWBt395K+
         2ZkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758111229; x=1758716029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=e94Towh7kTrjAgzNQKvUvLh2VDpa/hLLt7P0h/8NBOw=;
        b=qRcWgILninxsgLhxT8mhRaz2Ci5Vwo3i+jKlmAib9q+apX5XVhvnP86LMn5Cbl7wp/
         JnPhqQtBK4M1HlAFa6kf+pzZhjV24YmZ46pFTctqpB6CvgrPnwogPtYQXIGIw1GmdoxK
         a4D2X2eyl2VmwhtfRrWi1Nwk/uhXKpTkwvI2h9NNLQyEBcJYKXO1DhPKMgnEfFli5Y8u
         e8T68q4LAew1iZvZ5wcEHdd4C3r5GyG33WBehN8fPavd0Vmhx/pVpzAC+kBHCemWTII/
         LhBnUbuzu6vazL5eBZFvlIyuaakdpM7zE+q8TTIPPYA3q7WzZd62TU+6ElZINvA5PoMC
         iGBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOdvAOMjMT8PR9c88/RLtVQmx5vnpyvSjE7RrtzVZVBPvUqxc5t+WF2F1r4gferDbbk3/iPg==@lfdr.de
X-Gm-Message-State: AOJu0YzZnv6LNlMuZ+CZzXvbHt8xTxVGMpsk8BQM6ORr8b3TR9qduGlV
	VAEeN/t/3aKsAXGiDlDv7/KJSjDp66B3Fca+3R3NKSV04liNatumFcig
X-Google-Smtp-Source: AGHT+IEHKkUalJ4ttr2grY9JgYbJmQYKhUViIRzK54eaWeE52A/1G2mmVUmVzXzUuKz0h8jSqlBnjg==
X-Received: by 2002:a05:600c:1d1a:b0:45d:e326:96e7 with SMTP id 5b1f17b1804b1-46206b20d8bmr9147955e9.29.1758096209783;
        Wed, 17 Sep 2025 01:03:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4B+yuMliZDS6BLdiEPi1prvqBmGCAQ07CCAPRZXRab8w==
Received: by 2002:a05:600c:4e55:b0:459:e1a3:c3bc with SMTP id
 5b1f17b1804b1-45f2b20789els24966455e9.1.-pod-prod-09-eu; Wed, 17 Sep 2025
 01:03:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAPwvfceu0Yfp8R3NuPGFY+3o2pEZy9kY+sgefAFQWGzmSvtq6CUG4mnhxXGvGEO9xwOTBB4u9klI=@googlegroups.com
X-Received: by 2002:a05:600c:a44:b0:45a:236a:23ba with SMTP id 5b1f17b1804b1-46206099d89mr9775235e9.22.1758096207080;
        Wed, 17 Sep 2025 01:03:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758096207; cv=none;
        d=google.com; s=arc-20240605;
        b=ZM0yKu+roK4JAsCF2to4KaPHaZ2x319NAxgPL1zkldAKwz6Y2+NR3vLSijEiBRBhUh
         Uo6le9S8FY5XJzDqNXQz9+afba4KjEG3eAKn/BhWVLfTgv5u6C0JBLq5vAh/i6xCzJAv
         dLsMEpJwHtvRq+VGeG9T+inJn2e+gDPJ5J/lWgp7z8H1FFHwC9hne+HTLFgJTLPuQP5N
         E611lZq1A6bkQbEi18k77Xdfj3tkFSVlbasfwm2p5h3Krz/scfr7aCEpNvb00MjN9Usk
         k1f9aAn2oPfwJOqxCSzdpRyBCfYUluW+/7dirjG/eGnfuxjV1kX08fWKSHGpqg1jynPc
         WmBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=+OplWbxohq2Y5jWPghR/7x7wh7443bAXi+C38uXRXQ8=;
        fh=Wb3HipKmkT4lMHdSDcWFzql1v4gECtOWzbxTz9lgeo8=;
        b=L8w4zq1fC+/iHSnVYsMacQ3E/zmak1lglAknhwCMxwNQMfMf0rczrnGhxRCeY1KHbl
         LhRJFgK1KhEBkgCAgmJZ2YpvEAbsfcL9Sn8FWNouE/zvrskcHYUhoT1Vb44J+DJvI6ge
         WjW01qGT7TVcy0sYX4BU4Llj1NvDXcKkVefOfqOXcdiKC74QG2hf2dhYJK6n1OIObeos
         EVrU94fGkRxlu/E69WtCql9Apj20yJsrM/GnpC7+TLcNY+EUqDaS4QKT0iIPHCzRQfQD
         JvAqcqdx3fUMkhflFs0T/mdQOPADfD9xCoNQMcaHBARJu0gSI4ygyH1OlV75upLVZjfy
         PlDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LnEjgxL2;
       dkim=neutral (no key) header.i=@suse.cz header.b=UufgrTS2;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LnEjgxL2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=UufgrTS2;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f80f7944dsi837225e9.0.2025.09.17.01.03.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 01:03:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6FFF91F76B;
	Wed, 17 Sep 2025 08:03:26 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5DEDD137C3;
	Wed, 17 Sep 2025 08:03:26 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id r/GZFk5rymgYfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 17 Sep 2025 08:03:26 +0000
Message-ID: <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
Date: Wed, 17 Sep 2025 10:03:26 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [linux-next:master] [slab] db93cdd664:
 BUG:kernel_NULL_pointer_dereference,address
Content-Language: en-US
To: kernel test robot <oliver.sang@intel.com>,
 Alexei Starovoitov <ast@kernel.org>, Harry Yoo <harry.yoo@oracle.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org, linux-mm@kvack.org
References: <202509171214.912d5ac-lkp@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <202509171214.912d5ac-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.998];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_SEVEN(0.00)[8];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=LnEjgxL2;       dkim=neutral
 (no key) header.i=@suse.cz header.b=UufgrTS2;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=LnEjgxL2;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=UufgrTS2;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On 9/17/25 07:01, kernel test robot wrote:
> 
> 
> Hello,
> 
> kernel test robot noticed "BUG:kernel_NULL_pointer_dereference,address" on:
> 
> commit: db93cdd664fa02de9be883dd29343b21d8fc790f ("slab: Introduce kmalloc_nolock() and kfree_nolock().")
> https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master
> 
> in testcase: boot
> 
> config: i386-randconfig-062-20250913
> compiler: clang-20
> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> 
> (please refer to attached dmesg/kmsg for entire log/backtrace)
> 
> 
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202509171214.912d5ac-lkp@intel.com
> 
> 
> [    7.101117][    T0] BUG: kernel NULL pointer dereference, address: 00000010
> [    7.102290][    T0] #PF: supervisor read access in kernel mode
> [    7.103219][    T0] #PF: error_code(0x0000) - not-present page
> [    7.104161][    T0] *pde = 00000000
> [    7.104762][    T0] Thread overran stack, or stack corrupted

Note this.

> [    7.105726][    T0] Oops: Oops: 0000 [#1]
> [    7.106410][    T0] CPU: 0 UID: 0 PID: 0 Comm: swapper Tainted: G                T   6.17.0-rc3-00014-gdb93cdd664fa #1 NONE  40eff3b43e4f0000b061f2e660abd0b2911f31b1
> [    7.108712][    T0] Tainted: [T]=RANDSTRUCT
> [    7.109368][    T0] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
> [ 7.110952][ T0] EIP: kmalloc_nolock_noprof (mm/slub.c:5607) 

That's here.
if (!(s->flags & __CMPXCHG_DOUBLE) && !kmem_cache_debug(s))

dmesg already contains line "SLUB: HWalign=64, Order=0-3, MinObjects=0,
CPUs=1, Nodes=1" so all kmem caches are fully initialized, so doesn't look
like a bootstrap issue. Probably it's due to the stack overflow and not
actual bug on this line.

Because of that it's also unable to print the backtrace. But the only
kmallock_nolock usage for now is in slub itself, alloc_slab_obj_exts():

        /* Prevent recursive extension vector allocation */
        gfp |= __GFP_NO_OBJ_EXT;
        if (unlikely(!allow_spin)) {
                size_t sz = objects * sizeof(struct slabobj_ext);

                vec = kmalloc_nolock(sz, __GFP_ZERO, slab_nid(slab));
        } else {
                vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
                                   slab_nid(slab));
        }

Prevent recursive... hm? And we had stack overflow?
Also .config has CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=y

So, this?
diff --git a/mm/slub.c b/mm/slub.c
index 837ee037abb5..c4f17ac6e4b6 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2092,7 +2092,8 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 	if (unlikely(!allow_spin)) {
 		size_t sz = objects * sizeof(struct slabobj_ext);
 
-		vec = kmalloc_nolock(sz, __GFP_ZERO, slab_nid(slab));
+		vec = kmalloc_nolock(sz, __GFP_ZERO | __GFP_NO_OBJ_EXT,
+				     slab_nid(slab));
 	} else {
 		vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 				   slab_nid(slab));
@@ -5591,7 +5592,8 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	bool can_retry = true;
 	void *ret = ERR_PTR(-EBUSY);
 
-	VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO));
+	VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO |
+				      __GFP_NO_OBJ_EXT));
 
 	if (unlikely(!size))
 		return ZERO_SIZE_PTR;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4%40suse.cz.
