Return-Path: <kasan-dev+bncBCSL7B6LWYHBBHHRVKNQMGQEI6COE6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F1B8621D6F
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Nov 2022 21:14:21 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id h13-20020a0565123c8d00b004a47f36681asf5217210lfv.7
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Nov 2022 12:14:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1667938461; cv=pass;
        d=google.com; s=arc-20160816;
        b=o8uq2Ma3Op/S2GZre9rB1+sxfsAhq+GQkPZoQVM3Sfg8ujxtHSqcXUAubqD87yX8/s
         W9ZZWxU3b3WWaPjtUgr4cAIFzzVyZIgKL44x6Op6dxL3rcDRim8dUcrsHtrzNH019A/b
         xrcySqGx89OQeiBm5A787BkOunuDjq3fAmDOCYP58EgMAf7GiDFORUQ329/bcZO3wLa7
         8GcN0ondguvidCq44qQLlh6C3VCgLMRay5qlEtcvKrXJVqsYT0lF0Sd0s2erWPQM3AWp
         ScW6Ol5V6zgDLunhZFX14M9/u0NqjK/DROg+yNZlrXSMGJGLNGqg6Qb73n9SHJrk1zhw
         9siw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=IVKvQV3AZQdNAUJkTRdmV8I13eI+kXZ5d210zSHETT0=;
        b=nnYRIeeladFtBUNz5qSbNIRY2yb4z2pNFheklHx7+UmXJbgVfTc1IfTlprtUG+zlZg
         fWyCtKVlsnB7DVKsB+IWBNNQgeDJZKg4VI6wawZ8/iS6+RyNFhUG4sD6+gDZp3fnBGkQ
         vVlY8ka2I869Qk4azekLZB8B4iBUHjhC0Ej4TGpMbhSKrFExjqQVcj272LwbRd64ZNny
         vwv7YC1t9eOib/O6xU/dIOZdBAXjDt9hWnBxf63Mk6MDhT5qt1HY9QAQaGImJXHDSUoj
         R0d97ulLKacJ4R6PNOddxiU6iQO4p3R60lPJNqBhDwHIZj16mZooU6VZxtH/laSfBTTv
         sQ7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dygAqBZw;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IVKvQV3AZQdNAUJkTRdmV8I13eI+kXZ5d210zSHETT0=;
        b=pNbUcakr4d5Zk5LPgsJU/FEezObPtic+5Z5EAsrlEMH0UNSZZDbX3EHzibPmpqjD3f
         ACgid/NSSyRqXxr2w0FDLMZkXkPvlsqUniXYVdOD5v9sE9R/RIyk2GwG72vzLJMXMeNP
         KwN8+i36O1v7mvY6PHhm8h3nioGJptt6nkD06vmPFMT8wqY7IJ355JYFOtKY3gkWnKZo
         3NfcHhCCnHd2fB/vXvrofe9DQOedS5ycLRMALQnMyBTzHSJaiX+YC3EYDaZzpEFFV8OW
         MS1+1sp5EFCNfpKKYMvG1TK0d1XCs8mXGfhUbkHecGX6UQKPOKWC3tAShPHC2jNe1v3I
         k0kA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IVKvQV3AZQdNAUJkTRdmV8I13eI+kXZ5d210zSHETT0=;
        b=Uo3TtKdOzbygZvqiDE2wN4FpKUtdaNfYyO/5412VJhOn0PMaejx1WyW22gUdAaYEVB
         AftMqy/32zEnHef/nL/dYDT75l3BEGFp8x/2qka03EGwJbqpe0RA/IlE8xAiUdpDnCVE
         eKGQ4IBXcGRsorDUtPlREZ7NudD33GQGfhr19c9pPVU/Jhqgg1XqFYptNtTmrI/rChXN
         +X5bQP2oOuMpEQaRE+2UMFdw8Q7tdmHxuTP51x0jSb955mj8WdS6tO3LKtOwcgNoBhKT
         I4Lf/ULnNBgFW/WGlLwXuaejljGVKRXHiJZcchd+I70U+9yQ+k7kW2KSRL82bXlbblx8
         kseg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IVKvQV3AZQdNAUJkTRdmV8I13eI+kXZ5d210zSHETT0=;
        b=FbDz5/BSsFs/m0TAkL+bbLVL5tgfKqiDFJuH80whqw4gt60E7npusYCVj7amp7h/Ak
         LcFK+b0XbwyDM2hQFNPHaEi70jBnZtWSO1sX1PJTWCqHU7WVNeHC8Z2Jg4+jAgfPUgjT
         pJapc++qBtDuwhbS1ERiOa//PJm4xMAaX+tbBPW25XlXfnfNHIANbdvhPwcYtZqOmB2F
         2pZYpNiIDEpM4awtjb2CQlAD+SwLHnKMXTVyTshkfCuPiszeHcdnMBGdt3ZMPZJNPqIY
         dATWeWsLw1w3Anx25+nVUsv/IZwGvAhA78X3JZBtVM+ZSxQ2RMyJoFnh1funsTaEp6Tk
         pJSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3qbgsxbVb6VosBCbOMBC9WMy0a5bWenHIPi6IoheE3XO4wk4hO
	JJmfA4zRwig9jGZEBNp8g0A=
X-Google-Smtp-Source: AMsMyM7VlWuSIu13biWCAaIXcap8l1q5cWSzGX691ox2bZ9QQYqdQrALPNtfY9EvCtxrVYYdjeQKRg==
X-Received: by 2002:a19:c503:0:b0:4a2:b966:37ec with SMTP id w3-20020a19c503000000b004a2b96637ecmr22078552lfe.319.1667938460539;
        Tue, 08 Nov 2022 12:14:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9f4c:0:b0:26f:b780:6802 with SMTP id v12-20020a2e9f4c000000b0026fb7806802ls3410765ljk.0.-pod-prod-gmail;
 Tue, 08 Nov 2022 12:14:19 -0800 (PST)
X-Received: by 2002:a05:651c:1a0d:b0:277:113c:9e89 with SMTP id by13-20020a05651c1a0d00b00277113c9e89mr20265276ljb.245.1667938458922;
        Tue, 08 Nov 2022 12:14:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1667938458; cv=none;
        d=google.com; s=arc-20160816;
        b=v7xR3+Sr9psVkTI21J+fFDsqZo3Q+MR45DmB9di6zZjK8AuwHFWG/gzy7qyJPpzrIB
         AS281gfxxbL8enZJewDl8QPY/8Vn1rHDeqn/unE6rbnRlg7fwe9GO+wVXTV+5anCWTKl
         +sKuwhCjCORahu3kljXgwZmGx7TcDYbvjlu2ntg5HZp7bH1q2QQfUab34fS7eILGY0L5
         AKz6Cw8tc3jZJB3oXeaLdV0MiLnkP/+TylaDH+WzUYFlxlxW2DZLHrjfH0ghR3mzlOyF
         YDa6F86xl7n85mO9BEUAkL3lp7+rf3Q6q/unAvBwI5GeWn1J3NlDnNV8Lod/FbgMnZbG
         ZoTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=vec2jCz+Quh9+mCqYjMdMcKulUWOBt0A1f942dQxTI4=;
        b=gLriYPisUrcCXJPid9wxumgkzEVg86i8dLZA8IPr9aAEImaso6KVmfC9OURW4CAwni
         h5EtHrUo931PuUo2uxLPsvcXKeULjTscsxt5acKYlRCl2cWZXA3CWPpDKIU1Lj4BXqgz
         DZzcv1OFZCCfwGY41Tvzxe/wAh047kizlXBpW7LlJI2eHv4TLay4jUA60rrKcB529pM1
         15+LGlOVcxwVdyGqaCirIl+FUjBwjp91wg/Ut2daQzGATRGsy78wReR2SWWfq7HjUc+1
         HeGZQ1JzVFra6HDpReWU5x1AXAza2bl/di237k7RMPtLD1ADCEYT3FV7Bg78ydT8DQst
         jlIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dygAqBZw;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id c19-20020ac25f73000000b004abdb5d1128si380978lfc.2.2022.11.08.12.14.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Nov 2022 12:14:18 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id a15so22756727ljb.7
        for <kasan-dev@googlegroups.com>; Tue, 08 Nov 2022 12:14:18 -0800 (PST)
X-Received: by 2002:a2e:b163:0:b0:277:6bc:2ab0 with SMTP id a3-20020a2eb163000000b0027706bc2ab0mr6783632ljm.142.1667938458542;
        Tue, 08 Nov 2022 12:14:18 -0800 (PST)
Received: from [192.168.31.203] ([5.19.98.133])
        by smtp.gmail.com with ESMTPSA id v6-20020a05651203a600b004b40c1f1c70sm392981lfp.212.2022.11.08.12.14.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Nov 2022 12:14:18 -0800 (PST)
Message-ID: <b5e31093-ac80-595b-1127-2a3e35913d86@gmail.com>
Date: Tue, 8 Nov 2022 23:14:18 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH] x86/mm: Populate KASAN shadow for per-CPU GDT mapping in
 CPU entry area
Content-Language: en-US
To: Sean Christopherson <seanjc@google.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski
 <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, x86@kernel.org
Cc: "H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org,
 syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
References: <20221104212433.1339826-1-seanjc@google.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20221104212433.1339826-1-seanjc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dygAqBZw;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::234
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 11/5/22 00:24, Sean Christopherson wrote:
> Bounce through cea_map_percpu_pages() when setting protections for the
> per-CPU GDT mapping so that KASAN populates a shadow for said mapping.
> Failure to populate the shadow will result in a not-present #PF during
> KASAN validation if the kernel performs a software lookup into the GDT.
> 
> The bug is most easily reproduced by doing a sigreturn with a garbage
> CS in the sigcontext, e.g.
> 
>   int main(void)
>   {
>     struct sigcontext regs;
> 
>     syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
>     syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
>     syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
> 
>     memset(&regs, 0, sizeof(regs));
>     regs.cs = 0x1d0;
>     syscall(__NR_rt_sigreturn);
>     return 0;
>   }
> 
> to coerce the kernel into doing a GDT lookup to compute CS.base when
> reading the instruction bytes on the subsequent #GP to determine whether
> or not the #GP is something the kernel should handle, e.g. to fixup UMIP
> violations or to emulate CLI/STI for IOPL=3 applications.
> 
>   BUG: unable to handle page fault for address: fffffbc8379ace00
>   #PF: supervisor read access in kernel mode
>   #PF: error_code(0x0000) - not-present page
>   PGD 16c03a067 P4D 16c03a067 PUD 15b990067 PMD 15b98f067 PTE 0
>   Oops: 0000 [#1] PREEMPT SMP KASAN
>   CPU: 3 PID: 851 Comm: r2 Not tainted 6.1.0-rc3-next-20221103+ #432
>   Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0 02/06/2015
>   RIP: 0010:kasan_check_range+0xdf/0x190
>   Call Trace:
>    <TASK>
>    get_desc+0xb0/0x1d0
>    insn_get_seg_base+0x104/0x270
>    insn_fetch_from_user+0x66/0x80
>    fixup_umip_exception+0xb1/0x530
>    exc_general_protection+0x181/0x210
>    asm_exc_general_protection+0x22/0x30
>   RIP: 0003:0x0
>   Code: Unable to access opcode bytes at 0xffffffffffffffd6.
>   RSP: 0003:0000000000000000 EFLAGS: 00000202
>   RAX: 0000000000000000 RBX: 0000000000000000 RCX: 00000000000001d0
>   RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
>   RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
>   R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
>   R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
>    </TASK>
> 
> Fixes: 9fd429c28073 ("x86/kasan: Map shadow for percpu pages on demand")
> Reported-by: syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Sean Christopherson <seanjc@google.com>
> ---
>  arch/x86/mm/cpu_entry_area.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/x86/mm/cpu_entry_area.c b/arch/x86/mm/cpu_entry_area.c
> index dff9001e5e12..4a6440461c10 100644
> --- a/arch/x86/mm/cpu_entry_area.c
> +++ b/arch/x86/mm/cpu_entry_area.c
> @@ -195,7 +195,7 @@ static void __init setup_cpu_entry_area(unsigned int cpu)
>  	pgprot_t tss_prot = PAGE_KERNEL;
>  #endif
>  
> -	cea_set_pte(&cea->gdt, get_cpu_gdt_paddr(cpu), gdt_prot);
> +	cea_map_percpu_pages(&cea->gdt, get_cpu_gdt_rw(cpu), 1, gdt_prot);


I'm thinking using kasan_populate_shadow_for_vaddr() in cea_map_percpu_page() wasn't the right idea.
We should just map shadow for entire 'cea' from setup_cpu_entry_area() instead of fixing it up in random places.
I mean like this:

---
 arch/x86/mm/cpu_entry_area.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/x86/mm/cpu_entry_area.c b/arch/x86/mm/cpu_entry_area.c
index dff9001e5e12..b122fa5e805b 100644
--- a/arch/x86/mm/cpu_entry_area.c
+++ b/arch/x86/mm/cpu_entry_area.c
@@ -195,6 +195,9 @@ static void __init setup_cpu_entry_area(unsigned int cpu)
 	pgprot_t tss_prot = PAGE_KERNEL;
 #endif
 
+	kasan_populate_shadow_for_vaddr(cea, CPU_ENTRY_AREA_SIZE,
+					early_cpu_to_node(cpu));
+
 	cea_set_pte(&cea->gdt, get_cpu_gdt_paddr(cpu), gdt_prot);
 
 	cea_map_percpu_pages(&cea->entry_stack_page,
-- 
2.37.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b5e31093-ac80-595b-1127-2a3e35913d86%40gmail.com.
