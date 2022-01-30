Return-Path: <kasan-dev+bncBAABBWNX26HQMGQETMLGZQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BDBB4A32D8
	for <lists+kasan-dev@lfdr.de>; Sun, 30 Jan 2022 01:29:15 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id q7-20020a6bf207000000b006129589cb60sf7268676ioh.4
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Jan 2022 16:29:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643502554; cv=pass;
        d=google.com; s=arc-20160816;
        b=KvI2gdxY998BMR23L3NQY2DoQAy0SBiJSV+xHUErirNhKJhIExC4H+rDCVO8/jSGLk
         10NEn9vtH3uqWrVwvWb+0KHeqtCRUQTS3gdZqbxNIEP4VfpB1n6aYA27vY+6FvKtCOAK
         P2UIM/F52mGGy2ku+61uoAJfg9Y/pL/hEdlB5VC2fXwDxWQLedarzOujqPT6owjO0q+N
         pLtRQn6o6K9jy13ZkVlK9i57jHpzJFbe2LfTRPU/1EMFl1WnDODD1eWdVO4EDEGr1SjA
         dpLHe0Bt07rC75DtN7xtr8SMZRtJi1/rnHbn+sPeiaGP9aVstxM3Nwf7P+Hjrj36JeDX
         B41g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Jm+eS5otrqpPmZXl3SZhsypCrSa/uj1z4qe2Kyf9wDQ=;
        b=Hi3wkTGU7Lub18DK9lP9PbZ74SUL0EbAiHyV3o7r+vA2ODC1t2nfQHtHlFHtRr2IXN
         Xsre3J+oHWii/y3KJi7msrWDNJOStZfl6GAA7l/mpeUoVFZP8LNlGPrgaNVdrQhGnPgs
         bfmsZw2rb1ss72DCxM5skyZuL+eF+bdcpvPtSDLpJsvufjUD7Ggptt/T4/FnbP6WyICE
         U5HwiOwZIAc9Jkm3B2PUKYjnbF9e6dbQ3BYOX4Y9P7ioCnTHW411Iz55+kxOOI2xikw6
         21l3qWYyQchdP4A4pR+uJqbV/KIea08MVtwAwGuKuz19lZkED3hAJRNXMvFRUHv7lT2i
         RXSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jm+eS5otrqpPmZXl3SZhsypCrSa/uj1z4qe2Kyf9wDQ=;
        b=iW7gvSRM0QRoGIre2rAUIfqaW7lDl0qzYNhgpfEHa6ShwZYvdi1pglyT55nPlEYJrt
         ULWOT0cym8bo55gKVZbDvssbhrlnGyVXZpvXn1s4jRhHHfRC0Q1EechpRjiUeGQyM0Oe
         OxoKlMJCCEroYmSbzr8Giq+XqnjRqmEqJzWBU51L0pE7WDSF1BBzSH8y1bCl4CZNDOLI
         yOGkjbDCqpKwJVNzHpYoQk5Qii2D3mCG25NmZMK71Of8cXDzv6xgRuTObdDh9r5/TB2u
         5lKEz/a7gc8Da9UotEMXWW4cvvq9v51EP5z9WIqt9wfgEhYnUk/lgPDXGAg4ED8zW6Z7
         3VVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Jm+eS5otrqpPmZXl3SZhsypCrSa/uj1z4qe2Kyf9wDQ=;
        b=hdUw/lrwZmyGaRmQM/e5YrCy4mdwxoi6fn+/HnK0AUsAQaLUdoNRDDFidC/i5Fd8ls
         dX486W/UIJn5JMtI4huFIYj7pQFZSPbAYs4uUQK6ZQOKz1I4XpOODjNgp0IBrdNbc5SR
         p2ZFZhjq2hn1s8wKwBPVF9D+HMhusKHNOdqF52UCZNjpYid8QAiA1acT4tbex79wYlGi
         UMr9qdL7bZOOgUvTs4gr2GCB1Qqh+QFzp5tfTd6EzvBXtt3amvKzThovR3VKuQXotqmO
         733dBrBSOZ2SW1JeLFZLkwpX3cJVRPl3toOCTO7h+bKkj7K1mm44GIwtQZG/Zv4RuwAe
         BzqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530NfgSSUbx3khAWghe150PGZPQli4bdkRXC5dTZFGMeTbOudRzL
	lwX2lmocKUKxlnx1WGZHn+A=
X-Google-Smtp-Source: ABdhPJzrhjcfYqGXeIlBlkJLEx4SFmtgamMKI98ObuOnrKcRbFZcQYG1kEb7lNgtBPImnUITWDZTTA==
X-Received: by 2002:a05:6e02:5c3:: with SMTP id l3mr9864615ils.163.1643502554011;
        Sat, 29 Jan 2022 16:29:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6f4d:: with SMTP id b13ls2475724jae.0.gmail; Sat, 29 Jan
 2022 16:29:13 -0800 (PST)
X-Received: by 2002:a02:a1cd:: with SMTP id o13mr8309405jah.61.1643502553672;
        Sat, 29 Jan 2022 16:29:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643502553; cv=none;
        d=google.com; s=arc-20160816;
        b=fSmjUjirgzzQPpYXEa9F/BQJcCO3MUPYy+RumpP0LjvGRv1YzsNsrc5f2BbZDHaECr
         6k+Z+QCaomj3TQc0pMs54W0nyLJ3E53b3HTEQI8LKnW0ZYFXSH2ocmX9BdAVCKlGc0A6
         Td1kibLEF6iXUfI3jZkjvOpoBXLgcW6lQx5ZLJ7BpEcERknj5K1+xkbr6WmSfl4aNt/H
         VaiGTpTrAfg6j2Y67933JtBhuvrl5RO/y24e1LyzXWQUVarC9OXR8AbpDG1uo2MGnjMl
         ToZI5GioTAUgIMLHJSKp9j1TrCRRm5r8SBYyPMIR6i9lmUnCKg5jZG4wOe3CQyW97HQe
         6hLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=JiUK+Rh6eICDiTZndMokE0Gu06O6rhnv2lWdYziuwLs=;
        b=ZXpqZNjGd5KLsZ63LHBVqAYX4P+INoOgp/ejNyOvaDrYkWMpXI27BnBMEUvaEMFVb5
         fd/Sf6pF961zu43zht8QYH7S9kIeoBGQyQkJQrDEeoDKonm7jgZ1FWmQakwG/j+kgjpw
         u9gtA5HqpkXUve37m7QyCaecq52lbvG8GIK0uUWrFB/4M971xKP1CtXLasJdrE9PSqWp
         fiJoVLTM7SJgOw/P/T5JdDL+s05Qp8qusmqlvzuY97ksFXEAzikE6nSre6ufBj3rkwgD
         leGFvEsJ0doCFtJiDeFNkFbRSx/Xjj1SmYkhDChg3ymvb8mNhGC9O2l0/4Uadi7242cA
         5ehw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id v3si1499141jat.0.2022.01.29.16.29.12
        for <kasan-dev@googlegroups.com>;
        Sat, 29 Jan 2022 16:29:13 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from [192.168.68.105] (unknown [111.18.94.40])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9Dx3+LT2_VhH5IFAA--.18933S3;
	Sun, 30 Jan 2022 08:29:09 +0800 (CST)
Message-ID: <0e700c2c-8523-ebc3-f006-e463f1fb7d0f@loongson.cn>
Date: Sun, 30 Jan 2022 08:29:08 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Subject: Re: [PATCH 4/5] sched: unset panic_on_warn before calling panic()
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Baoquan He <bhe@redhat.com>, Jonathan Corbet <corbet@lwn.net>,
 Andrew Morton <akpm@linux-foundation.org>,
 Peter Zijlstra <peterz@infradead.org>, kexec@lists.infradead.org,
 linux-doc@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
 <1643370145-26831-5-git-send-email-yangtiezhu@loongson.cn>
 <CANpmjNPYYAy2jy_U_c7QjTsco6f1Hk2q=HP34di4YRMgdKsa+g@mail.gmail.com>
From: Tiezhu Yang <yangtiezhu@loongson.cn>
In-Reply-To: <CANpmjNPYYAy2jy_U_c7QjTsco6f1Hk2q=HP34di4YRMgdKsa+g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-CM-TRANSID: AQAAf9Dx3+LT2_VhH5IFAA--.18933S3
X-Coremail-Antispam: 1UD129KBjvJXoWxXF13Zr1xZFyftFWDGF43trb_yoWrCFyfpr
	n8KFZ2yr4kK34rXFZ7Xw4qyryYyws8Za4xGa4xJr4rt3Z8GF15JrWIkFy3tr1Ygw17Za4Y
	vw1jqry3Ca1kJaDanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUvGb7Iv0xC_Kw4lb4IE77IF4wAFF20E14v26r4j6ryUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Jr0_JF4l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVW8JVWxJwA2z4x0Y4vEx4
	A2jsIEc7CjxVAFwI0_Gr0_Gr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVACY4xI
	64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv67AKxVWUJVW8Jw
	Am72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkIwI1l
	c7I2V7IY0VAS07AlzVAYIcxG8wCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJV
	W8JwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF
	1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6x
	IIjxv20xvEc7CjxVAFwI0_Jr0_Gr1lIxAIcVCF04k26cxKx2IYs7xG6rW3Jr0E3s1lIxAI
	cVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x0267AKxVWUJVW8JbIYCTnIWIevJa
	73UjIFyTuYvjxUqEoXUUUUU
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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



On 1/28/22 19:52, Marco Elver wrote:
> On Fri, 28 Jan 2022 at 12:42, Tiezhu Yang <yangtiezhu@loongson.cn> wrote:
>>
>> As done in the full WARN() handler, panic_on_warn needs to be cleared
>> before calling panic() to avoid recursive panics.
>>
>> Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
>> ---
>>   kernel/sched/core.c | 11 ++++++++++-
>>   1 file changed, 10 insertions(+), 1 deletion(-)
>>
>> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
>> index 848eaa0..f5b0886 100644
>> --- a/kernel/sched/core.c
>> +++ b/kernel/sched/core.c
>> @@ -5524,8 +5524,17 @@ static noinline void __schedule_bug(struct task_struct *prev)
>>                  pr_err("Preemption disabled at:");
>>                  print_ip_sym(KERN_ERR, preempt_disable_ip);
>>          }
>> -       if (panic_on_warn)
>> +
>> +       if (panic_on_warn) {
>> +               /*
>> +                * This thread may hit another WARN() in the panic path.
>> +                * Resetting this prevents additional WARN() from panicking the
>> +                * system on this thread.  Other threads are blocked by the
>> +                * panic_mutex in panic().
>> +                */
>> +               panic_on_warn = 0;
>>                  panic("scheduling while atomic\n");
> 
> I agree this is worth fixing.
> 
> But: Why can't the "panic_on_warn = 0" just be moved inside panic(),
> instead of copy-pasting this all over the place?

OK, it looks better.

Let me wait for some days, if no more comments, I will send v2
to move "panic_on_warn = 0" inside panic() and remove it from
the other places, like this:

diff --git a/kernel/panic.c b/kernel/panic.c
index 55b50e052ec3..95ba825522dd 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -185,6 +185,16 @@ void panic(const char *fmt, ...)
         int old_cpu, this_cpu;
         bool _crash_kexec_post_notifiers = crash_kexec_post_notifiers;

+       if (panic_on_warn) {
+               /*
+                * This thread may hit another WARN() in the panic path.
+                * Resetting this prevents additional WARN() from 
panicking the
+                * system on this thread.  Other threads are blocked by the
+                * panic_mutex in panic().
+                */
+               panic_on_warn = 0;
+       }
+
         /*
          * Disable local interrupts. This will prevent panic_smp_self_stop
          * from deadlocking the first cpu that invokes the panic, since
@@ -576,16 +586,8 @@ void __warn(const char *file, int line, void 
*caller, unsigned taint,
         if (regs)
                 show_regs(regs);

-       if (panic_on_warn) {
-               /*
-                * This thread may hit another WARN() in the panic path.
-                * Resetting this prevents additional WARN() from 
panicking the
-                * system on this thread.  Other threads are blocked by the
-                * panic_mutex in panic().
-                */
-               panic_on_warn = 0;
+       if (panic_on_warn)
                 panic("panic_on_warn set ...\n");
-       }

         if (!regs)
                 dump_stack();
diff --git a/lib/ubsan.c b/lib/ubsan.c
index bdc380ff5d5c..36bd75e33426 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -154,16 +154,8 @@ static void ubsan_epilogue(void)

         current->in_ubsan--;

-       if (panic_on_warn) {
-               /*
-                * This thread may hit another WARN() in the panic path.
-                * Resetting this prevents additional WARN() from 
panicking the
-                * system on this thread.  Other threads are blocked by the
-                * panic_mutex in panic().
-                */
-               panic_on_warn = 0;
+       if (panic_on_warn)
                 panic("panic_on_warn set ...\n");
-       }
  }

  void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 3ad9624dcc56..f14146563d41 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -117,16 +117,8 @@ static void end_report(unsigned long *flags, 
unsigned long addr)
 
pr_err("==================================================================\n");
         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
         spin_unlock_irqrestore(&report_lock, *flags);
-       if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, 
&kasan_flags)) {
-               /*
-                * This thread may hit another WARN() in the panic path.
-                * Resetting this prevents additional WARN() from 
panicking the
-                * system on this thread.  Other threads are blocked by the
-                * panic_mutex in panic().
-                */
-               panic_on_warn = 0;
+       if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
                 panic("panic_on_warn set ...\n");
-       }
         if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
                 panic("kasan.fault=panic set ...\n");
         kasan_enable_current();

Thanks,
Tiezhu

> 
> I may be missing something obvious why this hasn't been done before...
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0e700c2c-8523-ebc3-f006-e463f1fb7d0f%40loongson.cn.
