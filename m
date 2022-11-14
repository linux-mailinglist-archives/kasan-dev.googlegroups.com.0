Return-Path: <kasan-dev+bncBCSL7B6LWYHBBTMYZGNQMGQEF3DSU7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D285E628215
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 15:10:22 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id be20-20020a056512251400b004aa9aadf60csf3297788lfb.20
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 06:10:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668435022; cv=pass;
        d=google.com; s=arc-20160816;
        b=uMqbFJiRSM3ogCOvL1IiHFWtZgwYo/om6i7g5bQhuAW6luC5W7KW1V1tjB4B9gSUtf
         0Y19uELbcu2InHWt08LpKKrhArjyaK3SKaqlkm8loU1vcPOX56tfd501N1wu1Fuo+cT0
         kuy1smGR6A0bhbf8SWpBfXglHmAFpDi9BRC/KTa+L53u3LIgSY1xUFHIJRTLku/RLVzJ
         eCgZmL+LOp8LQbVaSWIjbXcixoYHN4mFeGH/P2FoDmaAcjayIFaEkz4k0gN37JDrLxXj
         XNUPJzv4d3BvxS4X+y3DtgSJLfLFtKTX9MReS72+0PFaLLIu8nBEWU1V+zd5j5bRZYw3
         HChA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=0U3cqb1gCM9i96Kfm4lNY0XP28LWgcjDTgSTEjPlFSo=;
        b=huLjSIv3NlVrTkBL1c/PVY9O5orczukcrqS4Fxl2yWDC8QbB6b0xcy3VIERpj6eyb5
         J3hmW0YrAl3nCHZ/ItrUH/vutPPm04DOcwsdDwX5ylKreZVDh6/21gkoZPSjWAOlGCbO
         GAYfxH+4dRXrIhrs7cHSepFS2AqW8aRPAEQTZb5p9SfEeROWiEtkildUDw2xGKCqiOSh
         C8Ow1Fgm/sFHo1X8k52Or+MOsCGo6NatBRTyn/Qdnkxq/RHOnMMrJHecQv+fzvSbGfIf
         qNN/e++pWaH3klGqE+W2YNhMZE79IaVTXJOI4+m8hdtJhfZ6OJtMvUBuyJsnCWzZ5w+0
         nEHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=cFFhslt4;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0U3cqb1gCM9i96Kfm4lNY0XP28LWgcjDTgSTEjPlFSo=;
        b=SB7KRAvSubS9/VVwmxl8aJ6yRUQi9tEspMka3o9uuQGN1SP+aKqmSRiizZdCRT7y+W
         sgfytFVox8atsa62IxMOxeljgLcc+TLoQAhK45zDP6xZO7i5hqYQIl5kz8UsZR4GdRME
         XzWHq85UOFiupPnoTdRKIOqo0dWq12p6grerNQDtDlAOA1xEUER4FqWjRo9OxmJo/uQH
         Olqzd2kVluEEDT4syG+U1oISOB9NQg/lBIA4XN2s7bOEb+U6REmL7RGX3kku2krbQfZX
         XsF+jDU+CYiULAOuxIro7JHLLJ5cTlyG9fJULu7BM/FjYFVO74b7JGB4wIcTK4AB6pBr
         YZ/A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0U3cqb1gCM9i96Kfm4lNY0XP28LWgcjDTgSTEjPlFSo=;
        b=dDEh9TIG88cy3u4paiSul9aIOcwTp65o0lej9w/weLzjlzHu4VlMhbPLh3iZYDp8Ut
         W8C16aDxsNsKga7Z+iBzwYdkT62rvs+AWslEy4zFJ08kcBS0CE8sm0Fe35+TdUxQjTbc
         pyz1VP/4bUt7NpDawPdb9OnNldWeYETqgpgeCmRATph7AnCoKBR9qz6VUEyVMOgAGzKm
         og76z+yTPYrMW0sotmQlCfG+6QsLqYTYuM8aSeKQUzqFxnzKEPBb56vbuR5cy39pzA9V
         al5kf3CroHvZVhknVvcm8ZsOePrDi7CE70TGE8pmrtxAhv4f6HO8lxCzOLd1ZvZmS8SX
         i4bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0U3cqb1gCM9i96Kfm4lNY0XP28LWgcjDTgSTEjPlFSo=;
        b=jUDMVoq0wxy71HupONPohjNNjBv84T4iZBh1t1jdXYxjUHjj8vmiOlfO6dMjMNF2Pf
         8bDr0AKdfOgcL2/n8MHnHQDcXWj9Ni1cHqf6WGe/ZAp5lZCL4QfzGleBCoXwCk5VGRhL
         C0jtdvZuNB4wwvFVELrA3t2ZtCADuBNUSiewy/5DZT9cQm9TAqPMLX4zs172RGGSJXKI
         8nzK5nrtlukIiJZp2I0gWtUn1qheLb9MPNAbUDqXArSuPe+sPHOEab1PTHqHEbrDNWYz
         255hU8UN1O9QxTt5IMXvAcid8V9aVOqUUQl6/dDCnA1+MWBBRtb038q2s4VE5JN3OpjJ
         A4tQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnCZUY9pEnBOXhb8Y7XX/F2JH2VHHNA9ysoxE6ugXXt1kjysKuo
	vWdmcYanmOsGolGV1Rm13Cs=
X-Google-Smtp-Source: AA0mqf5/Jc8KHYX5fEQ4EYVXwJDxwDvJ5Rc9MBRUIRmbayN+J4Ythzq43Ut4UT8CQNyIiC60Bl5naw==
X-Received: by 2002:a05:6512:20c8:b0:4a2:66f9:1491 with SMTP id u8-20020a05651220c800b004a266f91491mr4363579lfr.55.1668435021948;
        Mon, 14 Nov 2022 06:10:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ac2:0:b0:277:2e6e:e039 with SMTP id p2-20020a2e9ac2000000b002772e6ee039ls1743952ljj.9.-pod-prod-gmail;
 Mon, 14 Nov 2022 06:10:20 -0800 (PST)
X-Received: by 2002:a05:651c:1308:b0:277:70fb:8576 with SMTP id u8-20020a05651c130800b0027770fb8576mr3877531lja.106.1668435020529;
        Mon, 14 Nov 2022 06:10:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668435020; cv=none;
        d=google.com; s=arc-20160816;
        b=gwNOE8jdI0bzkI1DtpUogFNuMcRJVFPFs7dGBo0FjTAuqX7Mhh026XA8fhWmNq40wQ
         I1kIK+cZ+LIDB8rx5X/mUbtEmaNY1By2tT/vduLtW4ekCvkIm/uniEedrn93eph2LBoy
         xk5Dd29BR0nLutMucP1S6btmcjWbx3fNEZLp2w5+wZI6TGFLx00vaWAhHS1GItU8cQT+
         GQLOd4dM0ng0ufflIen+rgaZxVrh/HGSRpvUYMWp8mUD3Y586WKAiGnXhmAmP+B6/eE5
         qGViYX2LTW/UEZKPcdFMsWqr7LOFblArOPX78jJ32NVOBeyRRm7R9/AFxM+CcbC/FFxd
         D1tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=d2+SnyYb9w1A47HblbxnZ451UEd8FYwse9lGeC9APAQ=;
        b=ygIR0mQu/BeLVvy4rgF2+waaQ5SaDzHsSTYuOvsLbtr9xyb4Hf+oiElWpPZNuI91XR
         wL0GvtEu+2KwnkAMhmAwoADXAwlB2mqU2Agb9wnRR8Dfqwm5AQOECYbQ6q5hoCIajAM5
         cnfAAS9S1e83Z57tipjslDcUqpvfUJgGtrNTTdXe9O9Q5XpbfbJUvZIYTd+UmIOcl5a6
         5/6L9r5l/q0Kul7yn0J/39pm70G7MBnP5HACZ6FHjghmo0dzB1om9vA+w2Pf//2PBQV4
         +8EmBnhMRfOgsQAwDXrkdcGpb57w5ZjFl+0qQVctEjJSmm0tpZN+hCn5ZmlFXy3fD8Xr
         JPOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=cFFhslt4;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id u20-20020ac258d4000000b00492ce810d43si282226lfo.10.2022.11.14.06.10.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 06:10:20 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id u2so13327838ljl.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Nov 2022 06:10:20 -0800 (PST)
X-Received: by 2002:a2e:b16d:0:b0:26d:d603:8df2 with SMTP id a13-20020a2eb16d000000b0026dd6038df2mr3840546ljm.189.1668435020281;
        Mon, 14 Nov 2022 06:10:20 -0800 (PST)
Received: from ?IPV6:2a02:6b8:0:107:3e85:844d:5b1d:60a? ([2a02:6b8:0:107:3e85:844d:5b1d:60a])
        by smtp.gmail.com with ESMTPSA id u12-20020ac258cc000000b0049f87fb416dsm1848415lfo.12.2022.11.14.06.10.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 06:10:19 -0800 (PST)
Message-ID: <21c89067-7112-dc62-6fb3-d83e265eebd5@gmail.com>
Date: Mon, 14 Nov 2022 17:10:20 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.2
Subject: Re: [PATCH v2 2/5] x86/mm: Populate KASAN shadow for entire per-CPU
 range of CPU entry area
Content-Language: en-US
To: Sean Christopherson <seanjc@google.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski
 <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, x86@kernel.org
Cc: "H. Peter Anvin" <hpa@zytor.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com,
 syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
References: <20221110203504.1985010-1-seanjc@google.com>
 <20221110203504.1985010-3-seanjc@google.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20221110203504.1985010-3-seanjc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=cFFhslt4;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::230
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



On 11/10/22 23:35, Sean Christopherson wrote:
> Populate a KASAN shadow for the entire possible per-CPU range of the CPU
> entry area instead of requiring that each individual chunk map a shadow.
> Mapping shadows individually is error prone, e.g. the per-CPU GDT mapping
> was left behind, which can lead to not-present page faults during KASAN
> validation if the kernel performs a software lookup into the GDT.  The DS
> buffer is also likely affected.
> 
> The motivation for mapping the per-CPU areas on-demand was to avoid
> mapping the entire 512GiB range that's reserved for the CPU entry area,
> shaving a few bytes by not creating shadows for potentially unused memory
> was not a goal.
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
> Suggested-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Sean Christopherson <seanjc@google.com>
> ---
>  arch/x86/mm/cpu_entry_area.c | 8 +++-----
>  1 file changed, 3 insertions(+), 5 deletions(-)
> 

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/21c89067-7112-dc62-6fb3-d83e265eebd5%40gmail.com.
