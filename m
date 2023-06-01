Return-Path: <kasan-dev+bncBAABB5OQ4GRQMGQE43JK2QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B3B5719758
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jun 2023 11:44:23 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-7775a282e25sf73787139f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jun 2023 02:44:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685612662; cv=pass;
        d=google.com; s=arc-20160816;
        b=aW/JOMdOdjzerixLtax3xhrWCuYx/nbKoxGgehpvAahpyfiZd/Sl43al7Jp/S9dJqV
         m6Trt+fHqMxA0VVJjcvZuciEpq0hI9E2h+pFuEHuYC+9ftpdP292WpZ+k1fZMpbyAc68
         jsFfbLJ0XjEEtiRFxKfWjC+p5ZU2DqTjW+hXDgdmOr9Nv9HwISwOrtQSVZLeHupxwUPy
         Q7qBS52v4Sz/2uLHVQCLnLt0leKxhAlyCe4iQLoeRm/KRKhGha/Tn+mL4aV4yHuYjYue
         ZijxnvMFvf6SsCto2mJfyYFL3GFCmvCoAlwkR04LOZ7P9zHGaGasCbjh1D0UMyTmIavz
         TNHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=YV5ui8O8HTEs+PoU42+mP6RZ04BIcUNiRek3RcKn3m4=;
        b=P9kMci1WLGf864S6XlN92KxkebJaGxq4rktsMwE+elcXuMZMGatTrCachD+1uHafSx
         X2rSzAg3DOv61tb/R2FDOqsUpm6TxA5v6wl5uUgDwh0JaodqWiYgk9jTFPBA3F5HZV4/
         JrEipEYDR9THfQeVLMEZz2UIrdps7bjlLsbK5Jdl+vXoFWU6/ZxCWwu4nU8JcjsgDA6u
         41TCe8ljBYfD/dR942dCw8gsyZY9C3kgyn6mBKiLzmgivgdt9WJi4GBoykSWDDABEyX6
         FwHSdXkg/jtJ3qdInTqB5sETrJyMqME+C91flxYYY6b4zn39pKxckZ6NJe23CagJyHgh
         e6og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="j0G/p2GH";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685612662; x=1688204662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YV5ui8O8HTEs+PoU42+mP6RZ04BIcUNiRek3RcKn3m4=;
        b=luptZilVuRVb7YVtLXD5YvB2liKBnYSzvnqvBXSR6OYD7b2nhxArRGFYDZp7wN8qRN
         VdU857tDTMYI7++51JU8YBxV8Hj06PgqLX5XFMWGTG1yhi7BMeKTg9xEf0BTiNrDyYT3
         EBKbvHh0y9b5AbCNa50M9sdxQmgIUijRN9a02eQhjVoiL2XtbHhZWZG/jOa3dN/GgLnx
         P/Ndnm5c1dWRnL4ekaM+DFI7wLLsvnFGzpop9dl7RERVCQYJSjn7kL5LxwGYX5i807Ub
         8aE+j2uuwM+xuIRtw38aBiL1/bcORnIcetPeadNwxrOwZXgYfMKk7gw4PgGjUfUbmOiA
         BusA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685612662; x=1688204662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YV5ui8O8HTEs+PoU42+mP6RZ04BIcUNiRek3RcKn3m4=;
        b=Eeo2M0/fM7lhCufS6PSZO+VRQZd45amcd3R0/JSX+tiezooq8XV5IrAiuX+d8Yz6c6
         41wVtSKK1/NqWWiRxKR6ODMS1iLaMnKt9g7+cMTmU2LhbCiZVODkCPkE/HHSeZqGAFNr
         wDIgm4/es7Z56yP9msUXYUKgcVQcAduSlOq1BwsWdEi6X5wUt42hR/l+WHmlTDhaxds7
         VD+rRH1yxWcU8om1q9ghpDYXxRh5BrzmUL8PlCTL6slbMNzM/H1eFY3BXQa1mf5E1kq3
         Q4xEIhW/xoN9kOvN/kltlI+GnzytNtfCXFqXzDKmgFzCh+VPH5mxTNUUauF3Cbokw0xd
         Q+1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy2it+laDggzWtVpXnqaDZlgYlm16v5OB++F+2NTxnJSwB++NEE
	9u4PsYZm9fT0XjeYXmmg7G4=
X-Google-Smtp-Source: ACHHUZ42/30NdHVq1Cdba+r4e7LTl8lVnvtSWWI5Y+T61Vt83xSWxKpxSOiKz2w5rFtLDe4RjOl8+g==
X-Received: by 2002:a92:c144:0:b0:33a:d0f6:9133 with SMTP id b4-20020a92c144000000b0033ad0f69133mr5596175ilh.12.1685612662049;
        Thu, 01 Jun 2023 02:44:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c04:b0:33b:c1d6:ecd3 with SMTP id
 l4-20020a056e021c0400b0033bc1d6ecd3ls695562ilh.0.-pod-prod-04-us; Thu, 01 Jun
 2023 02:44:21 -0700 (PDT)
X-Received: by 2002:a6b:6402:0:b0:776:f992:78cf with SMTP id t2-20020a6b6402000000b00776f99278cfmr7243264iog.12.1685612661454;
        Thu, 01 Jun 2023 02:44:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685612661; cv=none;
        d=google.com; s=arc-20160816;
        b=D/gOdTOMp25LfemCrWEk7VclTPoU7r2943gpQMLtosNzKf7hZQY5vTk8wK5qjzoq63
         e8Z3LbgvitmhPcIyrRxOKuFhZWMH7sioGNJp3pymbXKlNcVUH/vLXEwyd8PwsyjKE30J
         hpicZ6pQ+kA+JgiNDbXZvxttFywKbGE2B+mXIPu0UGU6KrMGWC5c0L29q+6sW6SRH81I
         3YXFSEjroxA2u4xO36S+BM4bWRgh9M3V/vjBbiP+lY4CQMbg4gbxSfa5GiTrzuChRUUY
         ROS9aQ8+y9IG40xQLD94tTRqpbiAV/jd3Eo6qwksqpy63JMYcKiiwLVC4Qie8aRS2Nn+
         WApQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=1OGCUaqwjj81XbO6PzQ69bcZuVIJ42RbhviriF8y7f0=;
        b=R1pgJRev3ctI9+pZBcrzeEAcKwY4V7itRTMSuN/lOo3wpPW3hEdk5fc5bsl9Cgp2/r
         LFajkCTQ+jpCP62nnotiubSUNHdiNI2kxRxjf9d9DMpEUXQLCKSqSJPzjiJDkVRmjpuu
         UtQQ5E6hRVkA4E4vr7nX9KiXLd2yyKz/HWUvuQf3UP5ZKeeAKadu8qq/FHygUxDJml1U
         ubw88feCPRQamCLG54/Vc6r/+mzf2JgOTW5v3GF9v4Lluyoly84Ccb0nXyM2KhTjm2zV
         cU9Neo2LqvqSHRkDbzJG7uJfCA4f4BbhCiM6nSIDl/AbXzGWOJSa3OodnV+tVXjuw996
         Pegw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="j0G/p2GH";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id s7-20020a056638218700b0041abe5ca15bsi724629jaj.2.2023.06.01.02.44.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Jun 2023 02:44:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1D46060F76
	for <kasan-dev@googlegroups.com>; Thu,  1 Jun 2023 09:44:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 85A00C433D2
	for <kasan-dev@googlegroups.com>; Thu,  1 Jun 2023 09:44:20 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 7685CC43143; Thu,  1 Jun 2023 09:44:20 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198443] KCOV: trace arch/x86/kernel code
Date: Thu, 01 Jun 2023 09:44:20 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: pengfei.xu@intel.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P2
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198443-199747-RAxiYABA6I@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198443-199747@https.bugzilla.kernel.org/>
References: <bug-198443-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="j0G/p2GH";       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=198443

--- Comment #3 from xupengfe (pengfei.xu@intel.com) ---
I found I could use below item and enable at least SHSTK test.
KCOV_INSTRUMENT_alternative.o                 :=n
KCOV_INSTRUMENT_amd_gart_64.o                 :=n
KCOV_INSTRUMENT_amd_nb.o                      :=n
KCOV_INSTRUMENT_aperture_64.o                 :=n
KCOV_INSTRUMENT_audit_64.o                    :=n
KCOV_INSTRUMENT_bootflag.o                    :=n
KCOV_INSTRUMENT_callthunks.o                  :=n
KCOV_INSTRUMENT_check.o                       :=n
KCOV_INSTRUMENT_cpuid.mod.o                   :=n
KCOV_INSTRUMENT_cpuid.o                       :=n
KCOV_INSTRUMENT_crash_core_64.o               :=n
KCOV_INSTRUMENT_crash_dump_64.o               :=n
KCOV_INSTRUMENT_crash.o                       :=n
KCOV_INSTRUMENT_devicetree.o                  :=n
KCOV_INSTRUMENT_dumpstack_64.o                :=n
KCOV_INSTRUMENT_dumpstack.o                   :=n
KCOV_INSTRUMENT_e820.o                        :=n
KCOV_INSTRUMENT_early_printk.o                :=n
KCOV_INSTRUMENT_early-quirks.o                :=n
KCOV_INSTRUMENT_ebda.o                        :=n
KCOV_INSTRUMENT_espfix_64.o                   :=n
KCOV_INSTRUMENT_ftrace_64.o                   :=n
KCOV_INSTRUMENT_ftrace.o                      :=n
KCOV_INSTRUMENT_head_64.o                     :=n
KCOV_INSTRUMENT_head64.o                      :=n
KCOV_INSTRUMENT_hpet.o                        :=n
KCOV_INSTRUMENT_hw_breakpoint.o               :=n
KCOV_INSTRUMENT_i8237.o                       :=n
KCOV_INSTRUMENT_i8253.o                       :=n
KCOV_INSTRUMENT_i8259.o                       :=n
KCOV_INSTRUMENT_idt.o                         :=n
KCOV_INSTRUMENT_io_delay.o                    :=n
KCOV_INSTRUMENT_ioport.o                      :=n
KCOV_INSTRUMENT_irq_64.o                      :=n
KCOV_INSTRUMENT_irqflags.o                    :=n
KCOV_INSTRUMENT_irqinit.o                     :=n
KCOV_INSTRUMENT_irq.o                         :=n
KCOV_INSTRUMENT_irq_work.o                    :=n
KCOV_INSTRUMENT_itmt.o                        :=n
KCOV_INSTRUMENT_jailhouse.o                   :=n
KCOV_INSTRUMENT_jump_label.o                  :=n
KCOV_INSTRUMENT_kdebugfs.o                    :=n
KCOV_INSTRUMENT_kexec-bzimage64.o             :=n
KCOV_INSTRUMENT_kgdb.o                        :=n
KCOV_INSTRUMENT_ksysfs.o                      :=n
KCOV_INSTRUMENT_kvmclock.o                    :=n
KCOV_INSTRUMENT_kvm.o                         :=n
KCOV_INSTRUMENT_ldt.o                         :=n
KCOV_INSTRUMENT_machine_kexec_64.o            :=n
KCOV_INSTRUMENT_mmconf-fam10h_64.o            :=n
KCOV_INSTRUMENT_module.o                      :=n
KCOV_INSTRUMENT_mpparse.o                     :=n
KCOV_INSTRUMENT_msr.o                         :=n
KCOV_INSTRUMENT_nmi.o                         :=n
KCOV_INSTRUMENT_paravirt.o                    :=n
KCOV_INSTRUMENT_paravirt-spinlocks.o          :=n
KCOV_INSTRUMENT_pci-dma.o                     :=n
KCOV_INSTRUMENT_pcspeaker.o                   :=n
KCOV_INSTRUMENT_perf_regs.o                   :=n
KCOV_INSTRUMENT_platform-quirks.o             :=n
KCOV_INSTRUMENT_pmem.o                        :=n
KCOV_INSTRUMENT_probe_roms.o                  :=n
KCOV_INSTRUMENT_process_64.o                  :=n
KCOV_INSTRUMENT_process.o                     :=n
KCOV_INSTRUMENT_ptrace.o                      :=n
KCOV_INSTRUMENT_pvclock.o                     :=n
KCOV_INSTRUMENT_quirks.o                      :=n
KCOV_INSTRUMENT_reboot.o                      :=n
KCOV_INSTRUMENT_relocate_kernel_64.o          :=n
KCOV_INSTRUMENT_resource.o                    :=n
KCOV_INSTRUMENT_rethook.o                     :=n
KCOV_INSTRUMENT_rtc.o                         :=n
KCOV_INSTRUMENT_sched_ipcc.o                  :=n
KCOV_INSTRUMENT_setup.o                       :=n
KCOV_INSTRUMENT_setup_percpu.o                :=n
KCOV_INSTRUMENT_sev.o                         :=n
KCOV_INSTRUMENT_signal_32.o                   :=n
KCOV_INSTRUMENT_signal_64.o                   :=n
KCOV_INSTRUMENT_signal.o                      :=n
KCOV_INSTRUMENT_smpboot.o                     :=n
KCOV_INSTRUMENT_smp.o                         :=n
KCOV_INSTRUMENT_stacktrace.o                  :=n
KCOV_INSTRUMENT_static_call.o                 :=n
KCOV_INSTRUMENT_step.o                        :=n
KCOV_INSTRUMENT_sys_ia32.o                    :=n
KCOV_INSTRUMENT_sys_x86_64.o                  :=n
KCOV_INSTRUMENT_tboot.o                       :=n
KCOV_INSTRUMENT_time.o                        :=n
KCOV_INSTRUMENT_tls.o                         :=n
KCOV_INSTRUMENT_topology.o                    :=n
KCOV_INSTRUMENT_trace_clock.o                 :=n
KCOV_INSTRUMENT_trace.o                       :=n
KCOV_INSTRUMENT_tracepoint.o                  :=n
KCOV_INSTRUMENT_traps.o                       :=n
KCOV_INSTRUMENT_tsc_msr.o                     :=n
KCOV_INSTRUMENT_tsc.o                         :=n
KCOV_INSTRUMENT_tsc_sync.o                    :=n
KCOV_INSTRUMENT_umip.o                        :=n
KCOV_INSTRUMENT_unwind_frame.o                :=n
KCOV_INSTRUMENT_uprobes.o                     :=n
KCOV_INSTRUMENT_vsmp_64.o                     :=n
KCOV_INSTRUMENT_x86_init.o                    :=n


I will do more testing to think out some good way for it.
Thanks a lot for Dmitry's guidance!

Thanks!

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198443-199747-RAxiYABA6I%40https.bugzilla.kernel.org/.
