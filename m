Return-Path: <kasan-dev+bncBDW2JDUY5AORBVMI6SMAMGQE3GVO7MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 336AC5B4A53
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 23:40:39 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id y10-20020a4a9c0a000000b0047330d6f1c0sf2213192ooj.9
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 14:40:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662846037; cv=pass;
        d=google.com; s=arc-20160816;
        b=X9/JfKtPHvfDJUf8xSCX66sdPBjPhoDFWhJ1IhQoeB2p9NfHv5pOIMqEvPtz01l6wl
         buIBvZ9V43y/eJCjHRimnF2KbmKwSY4l3BQwMAxFUVbboUpnsGcswW/c2n4nLVzupq8L
         iPoYGJjKLvrvU6kMmQXfAvs27ATXFq9F1xcpUAOYHt7K6jeN2Pepc3VEjBjwXAaZptBT
         tQVh5Y3D5N67Qb7cLXDtbQyN3Y/3C5DW/vMB15uPxoxDFTEoG7sMmILJVaUd05A6c5NK
         p7KCEbetWdncFDrcBmQlSymTdHzf8/0JiHlbH9XqXby9ebySIGYiFGoZ6WfU684Pfwey
         oiJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Zgu5e/KDlV5MtjxRln4ePIc8Uf+8a40ZjzKhy79q+2Y=;
        b=iFzG+BljtHs48xl0P1Ulmq62OJBN9Ick0mh+3A6hc7q/5jtDgDFnKEWeviKGAmst67
         ZW2G4V+6h4d1V80tAv3vzb/nHzHvjqEarN0GxUlslqDfeRT6kZTahhvBMUPPqTQT0/Fp
         NZnr/lGLyhh3Zrj8wF5xzWlfXz2IEnVWFjuiEi83zn8QHgKZ1wbfHWhK9/0YfVY4VM2+
         HMx9bgp8dq7d8YcYHQf/vDT3pKHGDdLh1db3sL4+mVztgSF+wjIHhXIPycVWk46s+T5+
         4UEKSKRbY7klFbnVvo38J/rAwzGjcYvqEtlDbKytyYK3Wb0+yC2ySoN24UCXzry8FdmU
         UKDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IRjnD3bP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=Zgu5e/KDlV5MtjxRln4ePIc8Uf+8a40ZjzKhy79q+2Y=;
        b=btw6mRzs3cw+MD+vmjI2JY1nDXjvA8OVgoYqm5Y1KkQIBn7Uqa9UTP6JWk+i4VRjnO
         7h2NOh3SsqWV1mssIbIxEMs+EzxPn4aqjOUsoBBQBUgFnafR3mbKqHQplT/fK+dcXeS1
         ELtq9t9bv7K/9G+s+1IIQIZOBe0P0LwBOK74ZNnz1VSMyhltgDK/p1ysmRhNN718qsmu
         xr7lbRJnz/wAJieTMMMpk1zVN9oVks/C/pbfftfgjXbGdywOuDE9hXfjQbYRDeYdfao4
         /VOdkph6YF5MImz6HoKC+PnntSDG333bqFErvmrBFT0MurDO/3yIluWwM8EZRev0hDit
         1YmQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=Zgu5e/KDlV5MtjxRln4ePIc8Uf+8a40ZjzKhy79q+2Y=;
        b=na73Pu2BKK3ChaIBOE2ZcfsBpR2aCK2FKRyT1F3hqAAQEnSi8ZtGLMjaOrjQ7/nFnS
         5kPVtjp5cuVZX5Ma/Q77Hd/KI5ARkVzn24cU8XkGMK8fhXcubjpRy9hKxQEE4KELwmJv
         IoAM+qsGmZXJR+iBJP6UdQei6e//96FvjDxen+5mIclRE+2v4eFYG0w6PVAtKmFyNRn8
         SjiyADKHkfkaig+QlVCVHScPsfrARJfLPM9HEIjEzTbGU1ofhTHkr8Fjts2diuO9ia8p
         8fhd42NtDcCzCGmiRb50ahyjafXqxsecq7wbnAFvz9GIS2KH+sE4V1ZjqIy6uqIxszwa
         h9zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Zgu5e/KDlV5MtjxRln4ePIc8Uf+8a40ZjzKhy79q+2Y=;
        b=s7PvWukIiNdL3lVxSJ/CVlvdrDGNs6jouaNNR4KvshOkbLE35sLTljjC57Cmk2yB/6
         gGVb4Odcm+Zht/24vbOqK/KFCIeL2DFYgv9j9SXUoxb/DB1ZNLuouv/a+TJCbf2qPhhY
         ttS/DlGOQFDqwzcM6vWnPkcJlthk7HfAC80ZTMksL95866Mo/+hjeWZKEmAPsfmQefPx
         s3wEeMU2CzQlsbQsuKz4QJ7i2O+BzQ07C1An4VEvoXpXILSx9wyYlv+p0a+X/MnyKTwK
         ntj7OiNXPMIB34dbLC3UrxplQmSU9oy7JYP3O2Tqwj5UwXma2QKapOGf0D1iUke8ybGx
         Byiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1I+B6hz2l5qBkfl5QiT8vLRvcBIrz1FfEbrE0tbW6RmG/RlJOP
	4TzBdFvQRTGy5erllX+0Bl4=
X-Google-Smtp-Source: AA6agR7qV1QKueLJVpfKiAkzyr8F5P5LpR0AneeYVYj1eG1V3I16lj0hvGDIkGK/WVNpnetm7cBO0A==
X-Received: by 2002:a9d:7a55:0:b0:637:1874:a2cb with SMTP id z21-20020a9d7a55000000b006371874a2cbmr7676252otm.318.1662846037343;
        Sat, 10 Sep 2022 14:40:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4147:b0:127:2be3:37fc with SMTP id
 r7-20020a056870414700b001272be337fcls2940956oad.10.-pod-prod-gmail; Sat, 10
 Sep 2022 14:40:36 -0700 (PDT)
X-Received: by 2002:a05:6870:a925:b0:122:8314:b7a4 with SMTP id eq37-20020a056870a92500b001228314b7a4mr8290009oab.118.1662846036825;
        Sat, 10 Sep 2022 14:40:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662846036; cv=none;
        d=google.com; s=arc-20160816;
        b=kdGEjtUNtn8SiQoYK9C9tmzUKSyNdQhhELDowdJt6xiF1cz7KB1WEXeRKMHoxTEAxL
         bu/HxJSdmA4bIIzCx1+hA7QHAh3FsH88OhFdWN+IokiAVhGqjcis3vGJMCtGQ1MPnQWi
         4ElW6BT4R/2MFhby2ENJop7OpIhN7W5FXpgMyoRj7Y43ze2ZoKNEXKN9htusStHj1ah3
         XwYvk0KNgiiw1xW/pVvXjAUrhXVgoXfJfvLI0RG2/jBwJ+BogvxHCHMEJwE/irB+7AmO
         B1WqNFQo4OdYfssMNWg1aXYJB+NloRLq4jCtKKGTB1toPNtaxQr0cNJjJLM/5fz6khqB
         EX+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1rkaXGzitQ8uWDzj/RJ0ZVLihQPs/LjSy+ViYByz17c=;
        b=hUqRRbrapp4rOdMWtmAiur7a5L+IgU8bRfQT7DDJBk/vv5hMjjPIMVh8pP+F6Ii9/S
         UlYGiEXGwA0ZfA4eP+lf5faK2Y4tdV4Fuq0NDAI32TJkwiACcpklgcvlR6p9DpFCetF5
         03KVqU/iruajfE6MhHZWbukwaAQ1okk51wYCEwN1NgUku+e8Cy+JbK/sHen7QWmS6lJZ
         xTrHZv1vHGLrtyPW7JJh6adRJWNKHYzUv8Mi5EDIn6HsxRVDJZ0eUv62Jn8wazQgSUr6
         znC8UdgBXCRt5N1OprtIlivK8iCziJFMCB++WmnDlgs74XSU5VD89sgtYaUUGnyeSqDC
         6VgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IRjnD3bP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id g7-20020a9d1287000000b006371b439b4esi105209otg.5.2022.09.10.14.40.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 10 Sep 2022 14:40:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id d15so3641401qka.9
        for <kasan-dev@googlegroups.com>; Sat, 10 Sep 2022 14:40:36 -0700 (PDT)
X-Received: by 2002:a37:aac4:0:b0:6cb:d070:7842 with SMTP id
 t187-20020a37aac4000000b006cbd0707842mr9667946qke.386.1662846036279; Sat, 10
 Sep 2022 14:40:36 -0700 (PDT)
MIME-Version: 1.0
References: <20220910052426.943376-1-pcc@google.com>
In-Reply-To: <20220910052426.943376-1-pcc@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 10 Sep 2022 23:40:25 +0200
Message-ID: <CA+fCnZdwqOJaT+UXaRF_1Lu8661bxB2WOYb1TiXunBoXdvTBhg@mail.gmail.com>
Subject: Re: [PATCH] kasan: also display registers for reports from HW exceptions
To: Peter Collingbourne <pcc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=IRjnD3bP;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::730
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Sat, Sep 10, 2022 at 7:24 AM Peter Collingbourne <pcc@google.com> wrote:
>
> It is sometimes useful to know the values of the registers when a KASAN
> report is generated.

Hi Peter,

What are the cases when the register values are useful? They are
"corrupted" by KASAN runtime anyway and thus are not relevant to the
place in code where the bad access happened.

Thanks!

> We can do this easily for reports that resulted from
> a hardware exception by passing the struct pt_regs from the exception into
> the report function; do so.
>
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> ---
> Applies to -next.
>
>  arch/arm64/kernel/traps.c |  3 +--
>  arch/arm64/mm/fault.c     |  2 +-
>  include/linux/kasan.h     | 10 ++++++++++
>  mm/kasan/kasan.h          |  1 +
>  mm/kasan/report.c         | 27 ++++++++++++++++++++++-----
>  5 files changed, 35 insertions(+), 8 deletions(-)
>
> diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
> index b7fed33981f7..42f05f38c90a 100644
> --- a/arch/arm64/kernel/traps.c
> +++ b/arch/arm64/kernel/traps.c
> @@ -1019,9 +1019,8 @@ static int kasan_handler(struct pt_regs *regs, unsigned long esr)
>         bool write = esr & KASAN_ESR_WRITE;
>         size_t size = KASAN_ESR_SIZE(esr);
>         u64 addr = regs->regs[0];
> -       u64 pc = regs->pc;
>
> -       kasan_report(addr, size, write, pc);
> +       kasan_report_regs(addr, size, write, regs);
>
>         /*
>          * The instrumentation allows to control whether we can proceed after
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 5b391490e045..c4b91f5d8cc8 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -316,7 +316,7 @@ static void report_tag_fault(unsigned long addr, unsigned long esr,
>          * find out access size.
>          */
>         bool is_write = !!(esr & ESR_ELx_WNR);
> -       kasan_report(addr, 0, is_write, regs->pc);
> +       kasan_report_regs(addr, 0, is_write, regs);
>  }
>  #else
>  /* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d811b3d7d2a1..381aea149353 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -353,6 +353,16 @@ static inline void *kasan_reset_tag(const void *addr)
>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
>
> +/**
> + * kasan_report_regs - print a report about a bad memory access detected by KASAN
> + * @addr: address of the bad access
> + * @size: size of the bad access
> + * @is_write: whether the bad access is a write or a read
> + * @regs: register values at the point of the bad memory access
> + */
> +bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
> +                      struct pt_regs *regs);
> +
>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
>  static inline void *kasan_reset_tag(const void *addr)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index abbcc1b0eec5..39772c21a8ae 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -175,6 +175,7 @@ struct kasan_report_info {
>         size_t access_size;
>         bool is_write;
>         unsigned long ip;
> +       struct pt_regs *regs;
>
>         /* Filled in by the common reporting code. */
>         void *first_bad_addr;
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 39e8e5a80b82..eac9cd45b4a1 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -24,6 +24,7 @@
>  #include <linux/types.h>
>  #include <linux/kasan.h>
>  #include <linux/module.h>
> +#include <linux/sched/debug.h>
>  #include <linux/sched/task_stack.h>
>  #include <linux/uaccess.h>
>  #include <trace/events/error_report.h>
> @@ -284,7 +285,6 @@ static void print_address_description(void *addr, u8 tag,
>  {
>         struct page *page = addr_to_page(addr);
>
> -       dump_stack_lvl(KERN_ERR);
>         pr_err("\n");
>
>         if (info->cache && info->object) {
> @@ -394,11 +394,14 @@ static void print_report(struct kasan_report_info *info)
>                 kasan_print_tags(tag, info->first_bad_addr);
>         pr_err("\n");
>
> +       if (info->regs)
> +               show_regs(info->regs);
> +       else
> +               dump_stack_lvl(KERN_ERR);
> +
>         if (addr_has_metadata(addr)) {
>                 print_address_description(addr, tag, info);
>                 print_memory_metadata(info->first_bad_addr);
> -       } else {
> -               dump_stack_lvl(KERN_ERR);
>         }
>  }
>
> @@ -458,8 +461,8 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
>   * user_access_save/restore(): kasan_report_invalid_free() cannot be called
>   * from a UACCESS region, and kasan_report_async() is not used on x86.
>   */
> -bool kasan_report(unsigned long addr, size_t size, bool is_write,
> -                       unsigned long ip)
> +static bool __kasan_report(unsigned long addr, size_t size, bool is_write,
> +                       unsigned long ip, struct pt_regs *regs)
>  {
>         bool ret = true;
>         void *ptr = (void *)addr;
> @@ -480,6 +483,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>         info.access_size = size;
>         info.is_write = is_write;
>         info.ip = ip;
> +       info.regs = regs;
>
>         complete_report_info(&info);
>
> @@ -493,6 +497,19 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>         return ret;
>  }
>
> +bool kasan_report(unsigned long addr, size_t size, bool is_write,
> +                       unsigned long ip)
> +{
> +       return __kasan_report(addr, size, is_write, ip, NULL);
> +}
> +
> +bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
> +                      struct pt_regs *regs)
> +{
> +       return __kasan_report(addr, size, is_write, instruction_pointer(regs),
> +                             regs);
> +}
> +
>  #ifdef CONFIG_KASAN_HW_TAGS
>  void kasan_report_async(void)
>  {
> --
> 2.37.2.789.g6183377224-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdwqOJaT%2BUXaRF_1Lu8661bxB2WOYb1TiXunBoXdvTBhg%40mail.gmail.com.
