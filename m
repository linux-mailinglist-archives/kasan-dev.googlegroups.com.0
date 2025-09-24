Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB5T2HDAMGQEPWH6OKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 34E5DB9C304
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 22:50:17 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-78de70c9145sf7668136d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:50:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758747016; cv=pass;
        d=google.com; s=arc-20240605;
        b=cpNVDZQeyP73rWZNl8XgGR0ZU4sqaVY8saB5mRcUrLrbwwZW382kO//AFWeUYpezbQ
         rk97UZESv4TSwbQx6YmluRQ0/ApLxzSVhJVcU9xvuWhx/TM2NCTglv7Bbx5OEWyaCBMp
         9MEq5HoypvHDxQ4Kv+4g2UCLdjW86mICaxzwBtM5eGC/J0OHIFafh8v5Cl67e9/RMqJg
         thk/1JJ+PUqWsOndpN17I6Z0EJwVQqjvj9unb8D57YFQBzxYrIAer1ZuVY1hcfUUgKJ1
         bYF1BOr+YK87pJ/aGcxzrgJcXuu3FFyEoYFnALyk6YQ1oMlLyo+NiJ9RJtG07HUxWfzR
         439g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3a7HmM/uW20MJh4aCP3RwGeNXoU0yI8HPEXDr3Rjs3k=;
        fh=FqtBNgwgzJJErhFjdCwHXXDkaL7ITN+Qfu9fYO21Og8=;
        b=EjpSMSPbYaFX3rpF3zdp+AZWcqbaeBC0lsCg7tLetnHMh8kKWazveq/0S4XfxsoaiW
         8Qp0JpLLy5q51cOOXc05omlQ1sMIASfNTddmJA1toqKTBRq2daEtwTGGpM2kzrShyug1
         PUW9X0jgPJsCzzKc5M+cQ480R8cZvgg+f1sEtVfF+SeyLqtfFzZSPm6Kboh/N8YgYz3Z
         UC3ABZXjT28GJHrdZfoGfMhGF44j/dEia5GUsj3REAjpI87Tby/9eCjYdI1k7VsUd7AP
         Qh3bVWlUTk0O6bMxx6rCZFbCrtzOfxYTCHgPhzH1y7jsKvITyrzbOZUvcPbsPhlMs23V
         NLhA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nTCHn5kj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758747016; x=1759351816; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3a7HmM/uW20MJh4aCP3RwGeNXoU0yI8HPEXDr3Rjs3k=;
        b=V4L2f3hFWC7BOo4Gy2w5Y8VpLRWSCtbb2eSEJnEKegbMFZGLl+40cHGZYKySI4j1wX
         kIAXcvZGkHUwWrMTf66MXxBXl//sWDzGFREuvNYXzTB2HVMySBrbsrWCHunlMTCwuMd4
         ERc0Y+POi4lKb67McnDLYRfffFbpifHY0CmdGtOtin7m3WOLxF+UYIz1sXo/+mRUIdK+
         gk2Mv4ZsmVQLyaHLDQ+YIsQduB0jGL8whYqqbcvb3ETwDKzkW4N1RupJhUzEagtywM6+
         PVehoN0E9Bo5HY3wrcCRlCXLLGeD8/SUTloPljmhkAgCdofmenknx+27BMdj5F8h40Ad
         EvEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758747016; x=1759351816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3a7HmM/uW20MJh4aCP3RwGeNXoU0yI8HPEXDr3Rjs3k=;
        b=PZe7bhF/cow9FTPTEMQZgddAAZA7eu0iLmp5PHmFYqKvsSnLd5a6rVJ64FgI3QrBH+
         BaeFKOiPOD5+NeVP/P6vEpq/5X0Szxp16wt+dtwBmQl8MFLrmIyoz7gUkcJo+9RZoyE+
         9pGoAk2hz2x3fwcLSLL9u60k9H+E1ZaNGBS7qtA9FqzSTmFqjqHmdrXckwHR2o1IMCxy
         ny2hGss5Hshdzijayq9G0mKezSTTZGARAzqNkXmDSg83Qk6dr4ogxrokHM0YW20PoTNq
         8kqn1h2e78xJ++U4LWXer0fLZefOh0XUefTyW4SmoclocamoJ8vMAoXo/6KZogZtYqwn
         1Dsg==
X-Forwarded-Encrypted: i=2; AJvYcCUb/mCJwUbs7K6doIfyZtl0RrALbh7yLMW5ZFvSDSe1aMTXqIAZxeh5AcaJF0M2dSmGTNn6gA==@lfdr.de
X-Gm-Message-State: AOJu0YwEqEFO3CPU2dPh95Ny6D3OG0T8aVKy6o1XjIHa0k1AI+UDjh2F
	RPk0i6MUCnmRnMMoJLW9RR/zzmAI7tr7PFKI0bAzxMMU2U0ax3kTsrvE
X-Google-Smtp-Source: AGHT+IFlhRxxz9mol6pdDlh7SFAVXPEmflZVm/3+BUjf4J/kRUeRyu7hTIcKOHuFSQupL5EfZgwRiQ==
X-Received: by 2002:a05:6214:5185:b0:783:c657:6db0 with SMTP id 6a1803df08f44-7fc2c8a4f54mr20732136d6.14.1758747015589;
        Wed, 24 Sep 2025 13:50:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5+REhNt8AwbNqvtTFuw1Lb/6QG3EJ8nhK3rKyhWMOegQ=="
Received: by 2002:ad4:5589:0:b0:78e:136c:b6d8 with SMTP id 6a1803df08f44-7fd7f9730d2ls5884406d6.2.-pod-prod-07-us;
 Wed, 24 Sep 2025 13:50:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWe52NzgYW+Crde0g/ZF3xpAOcyadEgu8e6DaEC4aenHOeaVFoTufZ9GRYWPlAgHPky8wjrflIhVzw=@googlegroups.com
X-Received: by 2002:a05:6102:3596:b0:596:163e:c59f with SMTP id ada2fe7eead31-5acd91d9a50mr637314137.34.1758747014474;
        Wed, 24 Sep 2025 13:50:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758747014; cv=none;
        d=google.com; s=arc-20240605;
        b=TPPEjQPkdLjnKywjoiEWKCiObOGjVDBESN8Ph/9UfB/1qv6UGBGduP2EKEt0fQaRyH
         dtTGagVbYAkg1b2lJqYTGGuyDB9iUKCkwwy+I/Ur0xfh+FkkhKGQ27JhAR2jjGcXJyYh
         A7YPGhusvL2aSSXoTm2FFOauYNxtCjHT4cYnRXYNhSD4fLlNNqVKThykCU5KCVmgagZ6
         o2QdaVxY2ttT98uWFMGwdnxS/e3yDmnCH9iGBaSlPj4h4mXbZYAPbTidyRaCqNq1iFcc
         ukdDf8AmhZPnyMmiRrE8aSnnWE++ukWSEtejgzSOdnq0GwLW5Ts9OZ2T90HCY481nLzU
         5ibw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yUtonTzH+d6Koc9tBSC0pPXzcPpJLfBt1hfJF5PLabQ=;
        fh=WgqOc51jJK0ZKG+Fc6puAjaz6N1VOUySRizLYnfHRnQ=;
        b=djU4L/hs8rm8QiQffa+yZ9iBu7QSU8dbbORsXdUxURg8BIPEB7P8Ber+tYH7lt59pt
         hNWMUsTg18XsiH6/eJNNjsuODg32vQV+IPVukNfu968MZl6GlwkGuo40jVWn2LoNKLjP
         ihqVKfZJOLnHeZUNMIm/J1CqZUrXY+vjbSZsz8rm2GprG/gdjBb6Kk+76iNHRJS3WE9b
         okVvP13lbJhaKma882R1fzW49XFSBk2/gOmnno7wAaHWrOazc5XdKpguvyBGRHJlQ76w
         trnLOq0tiWH3pPBEsl5Yuf/b6xEzP9y1byZHt9+ufypjXHtUP2Febd95eOaXxPaliCR0
         +1Zg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nTCHn5kj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5ae24516065si5591137.0.2025.09.24.13.50.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 13:50:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-26e68904f0eso3020525ad.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 13:50:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVrZ1jCxmu4GEEM5xtu/YbazI2vpQk0YEAOBeEOxn/8Vwjz68o92D8WiJZivoCahHOIlokllz6PbZM=@googlegroups.com
X-Gm-Gg: ASbGncsWaRnWmkNZtpHtD0M7q9fCtUE+cgOwQt3/jqf7FKXNyQra8dqOdsF2l34GWsa
	DkTuJLbE2aTsI8/CGEJFrYRxuMh6Z9PDW6XuBvBEV9Qz+UycDIh4m4d3lKFCOXtzcrmY9B9YbZj
	X2wXmeT2cQ7lIkda4hhbQ2AE7R8kq4GSF2AkTKhPymKPHIBJc+LIun9ZVfSwG269EyDt+vupFia
	cSjb/Aji5gAxOD2n2XlF7gcllpGgRK84dqad/zNSVyZDLRGFkmKfvY=
X-Received: by 2002:a17:903:264b:b0:269:8059:83ab with SMTP id
 d9443c01a7336-27ed4ab545emr6206725ad.51.1758747013201; Wed, 24 Sep 2025
 13:50:13 -0700 (PDT)
MIME-Version: 1.0
References: <20250924115124.194940-1-wangjinchao600@gmail.com> <20250924115124.194940-7-wangjinchao600@gmail.com>
In-Reply-To: <20250924115124.194940-7-wangjinchao600@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Sep 2025 22:49:35 +0200
X-Gm-Features: AS18NWBgUAm60x7jbnTDK3WCQpUXDCFu_1mbN9k4BD6qrp1olQW-5h-0n2U9Y9E
Message-ID: <CANpmjNOuA3q3BweB9kTUpAX4CX1U25Pqa0Hiyt__=7zio81=Uw@mail.gmail.com>
Subject: Re: [PATCH v5 06/23] mm/ksw: add singleton /proc/kstackwatch interface
To: Jinchao Wang <wangjinchao600@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Randy Dunlap <rdunlap@infradead.org>, 
	Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, 
	Valentin Schneider <vschneid@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Ian Rogers <irogers@google.com>, Adrian Hunter <adrian.hunter@intel.com>, 
	"Liang, Kan" <kan.liang@linux.intel.com>, David Hildenbrand <david@redhat.com>, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Alice Ryhl <aliceryhl@google.com>, Sami Tolvanen <samitolvanen@google.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, Rong Xu <xur@google.com>, 
	Naveen N Rao <naveen@kernel.org>, David Kaplan <david.kaplan@amd.com>, 
	Andrii Nakryiko <andrii@kernel.org>, Jinjie Ruan <ruanjinjie@huawei.com>, 
	Nam Cao <namcao@linutronix.de>, workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org, 
	linux-mm@kvack.org, llvm@lists.linux.dev, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, "David S. Miller" <davem@davemloft.net>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, linux-trace-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nTCHn5kj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::636 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 24 Sept 2025 at 13:51, Jinchao Wang <wangjinchao600@gmail.com> wrote:
>
> Provide the /proc/kstackwatch file to read or update the configuration.
> Only a single process can open this file at a time, enforced using atomic
> config_file_busy, to prevent concurrent access.

Why is this in /proc and not debugfs?

> ksw_get_config() exposes the configuration pointer as const.
>
> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> ---
>  mm/kstackwatch/kernel.c      | 77 +++++++++++++++++++++++++++++++++++-
>  mm/kstackwatch/kstackwatch.h |  3 ++
>  2 files changed, 79 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
> index 3b7009033dd4..4a06ddadd9c7 100644
> --- a/mm/kstackwatch/kernel.c
> +++ b/mm/kstackwatch/kernel.c
> @@ -3,11 +3,15 @@
>
>  #include <linux/kstrtox.h>
>  #include <linux/module.h>
> +#include <linux/proc_fs.h>
> +#include <linux/seq_file.h>
>  #include <linux/string.h>
> +#include <linux/uaccess.h>
>
>  #include "kstackwatch.h"
>
>  static struct ksw_config *ksw_config;
> +static atomic_t config_file_busy = ATOMIC_INIT(0);
>
>  struct param_map {
>         const char *name;       /* long name */
> @@ -74,7 +78,7 @@ static int ksw_parse_param(struct ksw_config *config, const char *key,
>   * - sp_offset  |so (u16) : offset from stack pointer at func_offset
>   * - watch_len  |wl (u16) : watch length (1,2,4,8)
>   */
> -static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
> +static int ksw_parse_config(char *buf, struct ksw_config *config)
>  {
>         char *part, *key, *val;
>         int ret;
> @@ -109,18 +113,89 @@ static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
>         return 0;
>  }
>
> +static ssize_t kstackwatch_proc_write(struct file *file,
> +                                     const char __user *buffer, size_t count,
> +                                     loff_t *pos)
> +{
> +       char input[MAX_CONFIG_STR_LEN];
> +       int ret;
> +
> +       if (count == 0 || count >= sizeof(input))
> +               return -EINVAL;
> +
> +       if (copy_from_user(input, buffer, count))
> +               return -EFAULT;
> +
> +       input[count] = '\0';
> +       strim(input);
> +
> +       if (!strlen(input)) {
> +               pr_info("config cleared\n");
> +               return count;
> +       }
> +
> +       ret = ksw_parse_config(input, ksw_config);
> +       if (ret) {
> +               pr_err("Failed to parse config %d\n", ret);
> +               return ret;
> +       }
> +
> +       return count;
> +}
> +
> +static int kstackwatch_proc_show(struct seq_file *m, void *v)
> +{
> +       seq_printf(m, "%s\n", ksw_config->user_input);
> +       return 0;
> +}
> +
> +static int kstackwatch_proc_open(struct inode *inode, struct file *file)
> +{
> +       if (atomic_cmpxchg(&config_file_busy, 0, 1))
> +               return -EBUSY;
> +
> +       return single_open(file, kstackwatch_proc_show, NULL);
> +}
> +
> +static int kstackwatch_proc_release(struct inode *inode, struct file *file)
> +{
> +       atomic_set(&config_file_busy, 0);
> +       return single_release(inode, file);
> +}
> +
> +static const struct proc_ops kstackwatch_proc_ops = {
> +       .proc_open = kstackwatch_proc_open,
> +       .proc_read = seq_read,
> +       .proc_write = kstackwatch_proc_write,
> +       .proc_lseek = seq_lseek,
> +       .proc_release = kstackwatch_proc_release,
> +};
> +
> +const struct ksw_config *ksw_get_config(void)
> +{
> +       return ksw_config;
> +}
>  static int __init kstackwatch_init(void)
>  {
>         ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
>         if (!ksw_config)
>                 return -ENOMEM;
>
> +       if (!proc_create("kstackwatch", 0600, NULL, &kstackwatch_proc_ops)) {
> +               pr_err("create proc kstackwatch fail");
> +               kfree(ksw_config);
> +               return -ENOMEM;
> +       }
> +
>         pr_info("module loaded\n");
>         return 0;
>  }
>
>  static void __exit kstackwatch_exit(void)
>  {
> +       remove_proc_entry("kstackwatch", NULL);
> +       kfree(ksw_config->func_name);
> +       kfree(ksw_config->user_input);
>         kfree(ksw_config);
>
>         pr_info("module unloaded\n");
> diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
> index a7bad207f863..983125d5cf18 100644
> --- a/mm/kstackwatch/kstackwatch.h
> +++ b/mm/kstackwatch/kstackwatch.h
> @@ -29,4 +29,7 @@ struct ksw_config {
>         char *user_input;
>  };
>
> +// singleton, only modified in kernel.c
> +const struct ksw_config *ksw_get_config(void);
> +
>  #endif /* _KSTACKWATCH_H */
> --
> 2.43.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-7-wangjinchao600%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOuA3q3BweB9kTUpAX4CX1U25Pqa0Hiyt__%3D7zio81%3DUw%40mail.gmail.com.
