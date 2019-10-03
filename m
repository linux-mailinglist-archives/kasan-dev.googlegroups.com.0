Return-Path: <kasan-dev+bncBCMIZB7QWENRBFMX3DWAKGQEMTGTFTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 75507CA0A5
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 16:54:15 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id w1sf5642158ioj.9
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2019 07:54:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570114454; cv=pass;
        d=google.com; s=arc-20160816;
        b=D7P82VXLDBiEXdIlKE9bwpKh/T3MEJLPKrorqAEhoy5qaTlujm3I1JLUVi+RZR+8sA
         aQVr4aK4AsYE4XDjmtDNPZqI7nweIMF76YmTUdgBMd3nSp3l6PEQglla6HfGA4M4XTMJ
         9UJva2wq/vBRYKgIiJQzbUfCi6LhRVSqNS+VAaJIvHq/j2YaAOzh26WsjwG/uVYq6BUN
         l/E8HR445ffPmAEsmDc+0SWlI1RdekXnTdh7R+A5FjV5KmgB28KqN+SjslGKIONffsqr
         6GLjEGXf8BnufYtaLHRrYEpEdkwc/M1TYai66AKQkhjJOYkAioH+Sj+C6x/auJz0gyXn
         6O9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HiF3QtE7MRb6KKE3wWJZ3Es6GZw4QDTJ7zCvyAGei7E=;
        b=sOLceUNrqtpUkvFeamKRnZ6cRFEweUCV5BmoBcWxg/JIZMpuRS5osssl4f6utoc5Ze
         yWCkZXr3+NMWFt9+cJu2g5mBQR+Cgv7+LSJG1DFfgWwwTk+6uZHpV49XAcBafvJe4Ub+
         u/jhnSwer0H9E9cgIEzR3Oq3H39chx8CYxLQq45hZlVK/3iYNLHFkHD7q7oDmBV74UZk
         DryEf3lWJ59hTK/bohHpvbHF144O+qRs9AJNKYp8GvYaKB0AV2mKmK3TBnf3Q4mvTokQ
         46J6I8NAx52go5kPmPlfaxsAeVhn7z6IE0yhOPiDksjaGaBRqnnnVn+VxYGUaX864ws2
         6Xxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="R/HBctXO";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HiF3QtE7MRb6KKE3wWJZ3Es6GZw4QDTJ7zCvyAGei7E=;
        b=Z5obevnGciJXC14pQFfvZ9dhbTh6rIudw906Rx0seLE8JUh/XY5RfFIbdHhKFwUTRT
         Rdi8wGNMSLw7Ee6yeJ/P+JylhzrqOdfl1173Luk1fB1qvaNIRzqQt57geOsPXTrBL5Bo
         i+eCvjx1oRSTWDBQ/NKS5JS/QdaKLizbfxPpmxaY3XJmCGxh10EPyuRfIg2k6VJPzQeo
         +a/cjXtMD1FTBbuFO6+AnmOIJFPRbOB7odFnPT7iGXDqayFK8186a8kb1HRzjSMj8yrD
         RgufajVsSbOPp7UQEq1XJVps6c7giX1ZF6SpJJNseomqcH/B+6f7qnx7d6dEWN5Z446w
         pF8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HiF3QtE7MRb6KKE3wWJZ3Es6GZw4QDTJ7zCvyAGei7E=;
        b=lBhRseQg0NJcudHW5e/WkzivzPMvXy17iINum0jLf8SzHst4r+ncETgrXyHRfQ3djg
         /wZqc/103xRRvSyImsREfAYlFerK/R5pU50iwmzDxRt6hrqM9LOwJeI5xXyJstkXxWZp
         Wfkoaei8mlJaz50c6lIBcEg+sua1EW5oLb2IkfkwdNs/ieJDoIhxPHhHDiKGNxkGqvQC
         JxpDn0a7VyZCrcijskVbp/k+8LUmohUpD7aqpmptAeGWL54Ker6GPEfSNqfQxnteprBK
         eMSziQFcZ5TuIRH50S5I2Ds93CatAd5Ou2KNoJcoIRJMRexTMgywC4r0swX3qG9/jT9H
         q6xA==
X-Gm-Message-State: APjAAAWY75tNfKUZLNOBsYcDstQ9lLSmYdwlvIeNSmAf8JjNCM+svij6
	/bwqHKcZXKdS7DpSs8Hcluc=
X-Google-Smtp-Source: APXvYqwW3G4MpxG+Cc4Nu/q4vhZlrldDGXmqeEV994WBLE+504BlD089z19UJ5/04btS5TRu/tqYNw==
X-Received: by 2002:a6b:b8c3:: with SMTP id i186mr8558293iof.194.1570114454394;
        Thu, 03 Oct 2019 07:54:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9854:: with SMTP id p20ls1262310ios.9.gmail; Thu, 03 Oct
 2019 07:54:13 -0700 (PDT)
X-Received: by 2002:a5e:8a0a:: with SMTP id d10mr845620iok.121.1570114453154;
        Thu, 03 Oct 2019 07:54:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570114453; cv=none;
        d=google.com; s=arc-20160816;
        b=YjxILBi75gqAXR7zMgxiaYe53rI6l+sQ22znoiQlEgozbUowr+5ku6NV9smf1FNaVO
         ePg1OZFtIfcjQzyfQRh2D3AhVP26pxQh3CTvSj3BBtH8r2BkxW8CkfnIwbx5YeYDe4H8
         1mcx5gqNshEnjuDDFvr8CydzzVL2r6rY+O/xnDMJf8U49g0o5OYcsGTRI4Oehm1xGXdP
         o7ViDKPLD47gzNIDAB4A0gZm3jci8riMyQpd0ovrR3N1lGi5Hg9oJGiyiRkHB9SO4YyF
         EKD40XZpELy+dnKostGVm5OY1zORSrNYtNjcLsb7qmzjL+LMIaR+tM6yGGMPb1gaT4bR
         8Bug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BTr3LSymDwJchkLEsnB04LTDGo5fRwiRd1Hl9vtA70A=;
        b=eY9AE3FTjLelDIOlvpp/MdEvsIqASi2t8mM/5u3YVlhQ+pTtvIzva21P0/1isFwuM+
         +/AEuzSzG0f7PsD9qQt5c2Ib/KGNXhKYlaZ1PYhl/O86ALfWPq4O9ax0Yz4ri50ScP9F
         C5Mo0eHbzLExKI9Mzr/Z7zWppFfEYcqaopPo0lDwjIHYmRm8J6ttXGOrTsXXoGrtNhou
         NZ3FHEG41VLtmhl1FNOpnF530HfQofQoDkenvyrR2my8u/FzxNaUL1LZGoezJnPktnER
         SRvZ1haYgZvsvXTQ8NacB5QUxmO7EiD4eCdZWe5GRitJQOkWOXkpkLrZVjDOOXtOkjZV
         mQ/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="R/HBctXO";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id n201si228243iod.3.2019.10.03.07.54.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Oct 2019 07:54:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id u184so2651087qkd.4
        for <kasan-dev@googlegroups.com>; Thu, 03 Oct 2019 07:54:13 -0700 (PDT)
X-Received: by 2002:a37:985:: with SMTP id 127mr4662844qkj.43.1570114451897;
 Thu, 03 Oct 2019 07:54:11 -0700 (PDT)
MIME-Version: 1.0
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
 <1569594142.9045.24.camel@mtksdccf07> <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
 <1569818173.17361.19.camel@mtksdccf07> <1570018513.19702.36.camel@mtksdccf07>
 <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
 <1570069078.19702.57.camel@mtksdccf07> <CACT4Y+ZwNv2-QBrvuR2JvemovmKPQ9Ggrr=ZkdTg6xy_Ki6UAg@mail.gmail.com>
 <1570095525.19702.59.camel@mtksdccf07> <1570110681.19702.64.camel@mtksdccf07>
In-Reply-To: <1570110681.19702.64.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Oct 2019 16:53:59 +0200
Message-ID: <CACT4Y+aKrC8mtcDTVhM-So-TTLjOyFCD7r6jryWFH6i2he1WJA@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="R/HBctXO";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Oct 3, 2019 at 3:51 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:>
> how about this?
>
> commit fd64691026e7ccb8d2946d0804b0621ac177df38
> Author: Walter Wu <walter-zh.wu@mediatek.com>
> Date:   Fri Sep 27 09:54:18 2019 +0800
>
>     kasan: detect invalid size in memory operation function
>
>     It is an undefined behavior to pass a negative value to
> memset()/memcpy()/memmove()
>     , so need to be detected by KASAN.
>
>     KASAN report:
>
>      BUG: KASAN: invalid size 18446744073709551614 in
> kmalloc_memmove_invalid_size+0x70/0xa0
>
>      CPU: 1 PID: 91 Comm: cat Not tainted
> 5.3.0-rc1ajb-00001-g31943bbc21ce-dirty #7
>      Hardware name: linux,dummy-virt (DT)
>      Call trace:
>       dump_backtrace+0x0/0x278
>       show_stack+0x14/0x20
>       dump_stack+0x108/0x15c
>       print_address_description+0x64/0x368
>       __kasan_report+0x108/0x1a4
>       kasan_report+0xc/0x18
>       check_memory_region+0x15c/0x1b8
>       memmove+0x34/0x88
>       kmalloc_memmove_invalid_size+0x70/0xa0
>
>     [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
>
>     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
>     Reported-by: Dmitry Vyukov <dvyukov@google.com>
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index b63b367a94e8..e4e517a51860 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -280,6 +280,23 @@ static noinline void __init
> kmalloc_oob_in_memset(void)
>         kfree(ptr);
>  }
>
> +static noinline void __init kmalloc_memmove_invalid_size(void)
> +{
> +       char *ptr;
> +       size_t size = 64;
> +
> +       pr_info("invalid size in memmove\n");
> +       ptr = kmalloc(size, GFP_KERNEL);
> +       if (!ptr) {
> +               pr_err("Allocation failed\n");
> +               return;
> +       }
> +
> +       memset((char *)ptr, 0, 64);
> +       memmove((char *)ptr, (char *)ptr + 4, -2);
> +       kfree(ptr);
> +}
> +
>  static noinline void __init kmalloc_uaf(void)
>  {
>         char *ptr;
> @@ -734,6 +751,7 @@ static int __init kmalloc_tests_init(void)
>         kmalloc_oob_memset_4();
>         kmalloc_oob_memset_8();
>         kmalloc_oob_memset_16();
> +       kmalloc_memmove_invalid_size;
>         kmalloc_uaf();
>         kmalloc_uaf_memset();
>         kmalloc_uaf2();
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2277b82902d8..5fd377af7457 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
>  {
> -       check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> +       if(!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> +               return NULL;

Overall approach looks good to me.
A good question is what we should return here. All bets are off after
a report, but we still try to "minimize damage". One may argue for
returning addr here and in other functions. But the more I think about
this, the more I think it does not matter.


>         return __memset(addr, c, len);
>  }
> @@ -110,7 +111,8 @@ void *memset(void *addr, int c, size_t len)
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> +       if(!check_memory_region((unsigned long)src, len, false, _RET_IP_))
> +               return NULL;
>         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>
>         return __memmove(dest, src, len);
> @@ -119,7 +121,8 @@ void *memmove(void *dest, const void *src, size_t
> len)
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
>  {
> -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> +       if(!check_memory_region((unsigned long)src, len, false, _RET_IP_))
> +               return NULL;
>         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>
>         return __memcpy(dest, src, len);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 616f9dd82d12..02148a317d27 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -173,6 +173,11 @@ static __always_inline bool
> check_memory_region_inline(unsigned long addr,
>         if (unlikely(size == 0))
>                 return true;
>
> +       if (unlikely((long)size < 0)) {
> +               kasan_report(addr, size, write, ret_ip);
> +               return false;
> +       }
> +
>         if (unlikely((void *)addr <
>                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
>                 kasan_report(addr, size, write, ret_ip);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 0e5f965f1882..0cd317ef30f5 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -68,11 +68,16 @@ __setup("kasan_multi_shot", kasan_set_multi_shot);
>
>  static void print_error_description(struct kasan_access_info *info)
>  {
> -       pr_err("BUG: KASAN: %s in %pS\n",
> -               get_bug_type(info), (void *)info->ip);
> -       pr_err("%s of size %zu at addr %px by task %s/%d\n",
> -               info->is_write ? "Write" : "Read", info->access_size,
> -               info->access_addr, current->comm, task_pid_nr(current));
> +       if ((long)info->access_size < 0) {
> +               pr_err("BUG: KASAN: invalid size %zu in %pS\n",
> +                       info->access_size, (void *)info->ip);

I would not introduce a new bug type.
These are parsed and used by some systems, e.g. syzbot. If size is
user-controllable, then a new bug type for this will mean 2 bug
reports.
It also won't harm to print Read/Write, definitely the address, so no
reason to special case this out of a dozen of report formats.
This can qualify as out-of-bounds (definitely will cross some
bounds!), so I would change get_bug_type() to return
"slab-out-of-bounds" (as the most common OOB) in such case (with a
comment).


> +       } else {
> +               pr_err("BUG: KASAN: %s in %pS\n",
> +                       get_bug_type(info), (void *)info->ip);
> +               pr_err("%s of size %zu at addr %px by task %s/%d\n",
> +                       info->is_write ? "Write" : "Read", info->access_size,
> +                       info->access_addr, current->comm, task_pid_nr(current));
> +       }
>  }
>
>  static DEFINE_SPINLOCK(report_lock);
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 0e987c9ca052..b829535a3ad7 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t
> size, bool write,
>         if (unlikely(size == 0))
>                 return true;
>
> +       if (unlikely((long)size < 0)) {
> +               kasan_report(addr, size, write, ret_ip);
> +               return false;
> +       }
> +
>         tag = get_tag((const void *)addr);
>
>         /*
>
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570110681.19702.64.camel%40mtksdccf07.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaKrC8mtcDTVhM-So-TTLjOyFCD7r6jryWFH6i2he1WJA%40mail.gmail.com.
