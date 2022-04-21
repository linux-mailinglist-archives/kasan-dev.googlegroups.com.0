Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLWYQSJQMGQEL7D2TWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id DE755509D07
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 12:04:31 +0200 (CEST)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-2f4dee8688csf1274257b3.16
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 03:04:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650535470; cv=pass;
        d=google.com; s=arc-20160816;
        b=BzfuliUigzjn2srdnwJ3L5OB1xKPl7l4ykbynqx5tNWLRK6eYlNXFfXyGjPVPWU60u
         jgX6GJqZyf3nWwP51iEm4TF6MceTOBLtOFQhPHuSK95wgt10m3kklZoVDt7mzrC3OTn2
         cVFbyVnRDAx+yEAg85a2Mc9/tF9xR6lzS5HciUEGb+ob2eRG/HP2QBxhSuEPxynH/ZY1
         RuyrcMhO1DZy7gSxmlVVyryr8I+UofAghRpoKlOibyxdb5bNGRReZf9jIoOcIhTF2Vmn
         ktuh128863jT5kF7fGiZ6O0eu6dccYSFTiY3C9nJ33oPNMe/vJqmuimneIWJijjgJDqY
         tDJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uuozyUdRnq1kJF3HxmsuRn9RwqiybmlJ7sxcCgj5ch4=;
        b=L+zu/+V58H0eNocM7kH4553mWNd4Kz9FSmQAtoWueVOapQSLcOo0VesIew7/d09hW+
         PbmNV8zKpTRJ9q0TNb9umJZcCMYLP1LrTvh181EQjTtBD0nNS4k+vLlEbh8SgHz1Y1PJ
         flxo2u9xv0/40ZGhSti0cLgdwQ+kSp0UFasbwvZtt6jL+87woxph0QDrdEWpqzZy9MYO
         +RNrpBgixA0MxcVl6iwqwlfl0tAiRURhWBOgPAdAGvtEO1nDlc6p5ZQjNWXeR+Sm4Dre
         9u1LAGqpo9heIRNOZiRvrWjchy5ILxR5QBmGmHr9JNbgowve/VlCC48qwUBKWeHM5q5C
         RYGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ocgx+hoZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uuozyUdRnq1kJF3HxmsuRn9RwqiybmlJ7sxcCgj5ch4=;
        b=Odk0EhQ4tscaRpR1U1p/Dco3UqvwSt5Ei8/D7h/9sc9cIeXqgf7/nIKB+HSRJFwMgY
         MZVCM8sio5tuxe5Jts+lwFAL7pXZ3wmuWAjhzOA/Q/6z9a9QkA+YDpCpFf2mGAWHEVJj
         mb5mPQgaXIWanrqc69zeDOFFVCIRQZC2ncFGG8C/kBb9+vjghuJrTO/RUp/+kM11LLSy
         euQOWQ0hmvtTJVSihNObb1oAD+1N4h/N9MhX5uKAevLpNq/ylcYoOIsKp9ImyExapOPJ
         t4xHXkGuJOkg1d3yJyu2f/6GGN5MzHbzo56HfXyx7UwNikLWknE9zuBv3XgFgQaH6+hY
         p+IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uuozyUdRnq1kJF3HxmsuRn9RwqiybmlJ7sxcCgj5ch4=;
        b=jvRnf/6eN7dz7F1bvW0tMW/pibtqg5t5k1rO0nsRSp7wxY9jP7ElovNoNnKNdUXftV
         cDcNvyhB8xDnWpVUebinkTS8Ga6b4Wf1Qc1SIf6dAONQ5up3g8iVtvKpCi/1hsGsZsb9
         ofHgz0UnOgt7aeJZDb8xtOX1glMe4dRfm8nV9hq185e2z3+CXbwXQWPWU63v3ZS3GQH1
         WTH5ES/eEMtZd4sLVKz2jqNlZwBUtbg5zF38KMgjbqf1SbUzUebMgyM73+9AXnV0zZFk
         84xsMD9Rz0rdUWOdpH2dxFxAvckxH1eSlYoMKc6o+WVX5cRPyZinx8QhGPn6FybSRQg+
         88Wg==
X-Gm-Message-State: AOAM530NL1b/QTHoV8GbuRyFZBTI+WAnz8gn/UQCURbt5LoSMn53//p8
	6q1K3KgHp0/35MwZlYaQCyc=
X-Google-Smtp-Source: ABdhPJzYS6G6G9iAbV7w5IdTmT1hqF4enni9aKDzduu3mDpYv8uBZJpV95yHstpEW5a+qu1U+Y/1+g==
X-Received: by 2002:a25:3247:0:b0:641:379c:540e with SMTP id y68-20020a253247000000b00641379c540emr22861815yby.74.1650535470541;
        Thu, 21 Apr 2022 03:04:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1025:b0:645:7d52:a81c with SMTP id
 x5-20020a056902102500b006457d52a81cls155373ybt.3.gmail; Thu, 21 Apr 2022
 03:04:30 -0700 (PDT)
X-Received: by 2002:a05:6902:572:b0:641:4d70:5716 with SMTP id a18-20020a056902057200b006414d705716mr23285211ybt.397.1650535470052;
        Thu, 21 Apr 2022 03:04:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650535470; cv=none;
        d=google.com; s=arc-20160816;
        b=m/JfSnUfAD/mZYCwsXUyWiD0OBymaVdTopISxugg1LjgvPDyo/JzixjsIrIoE/XlaV
         FL0SPFMHB2IzSVJxaLhuo9YB/l8pDrSlOC+NtU0YAKenTsjsL+EWwL9outeECleA2qU+
         dS3TTeCsCrST0E/dKiVhfyglUXVcI63oJswQ4YRIvFXmVrq1dhdU3TzxrjAXXf0nWYuA
         yPII6hXJpuyDl6brJhJK3vaidTXizT6L9Rz2ay9CJpuhni7SyUdCiQ3XFAhgoiQMc7Np
         +xUIzZvYD9IHMHqY80rxCncP0niS237k1/yZBsL8ZpfHNBXW2H6awkNVrRc1GQiwflNX
         IpYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jYyPXLiEirgi7xpe02I4Hhb1NNjlliER4jXCeSNqs/s=;
        b=YHMf1cdRSTsKHKL/4WvVr4oT0nmumCZapI5SC6Uj3QCO3WZ2XjKF73FA7BM+deapjR
         GN42R9E9h1By2ZBWUnFA1KfCoXYZMQl2msGlZN1fxsDmXMoZE0y9QyijkpqsCvmbHEK/
         6yAwC4pVPmzoJONNtcoqRm5ZoCe+YTbSULevpnqKgGEPxlCWEEdPkyzjxP55ueJhYJ6A
         YZJkdC1xIfSj1KHRBkQOoLR8s77dzG+SFG27xhW51PEh2RxC8ku3sWsDp2/4z0ZAxjEZ
         XxoWaps3FinzCA5t0dldKUAR6dI225R9b7aqRBNBDPqloBk0byaMVmfb1hpUB/oTUJtI
         vY6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ocgx+hoZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id b15-20020a81340f000000b002e6be3040bcsi299514ywa.2.2022.04.21.03.04.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 03:04:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id m132so7843297ybm.4
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 03:04:30 -0700 (PDT)
X-Received: by 2002:a25:bb0f:0:b0:61d:60f9:aaf9 with SMTP id
 z15-20020a25bb0f000000b0061d60f9aaf9mr23093358ybg.199.1650535469600; Thu, 21
 Apr 2022 03:04:29 -0700 (PDT)
MIME-Version: 1.0
References: <20220420104927.59056-1-huangshaobo6@huawei.com>
In-Reply-To: <20220420104927.59056-1-huangshaobo6@huawei.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Apr 2022 12:03:53 +0200
Message-ID: <CAG_fn=Xs-OqpVCW5KyQLYKXNmQ4aH-KDjY0BrWpqMfPKcu-dug@mail.gmail.com>
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
To: Shaobo Huang <huangshaobo6@huawei.com>
Cc: Marco Elver <elver@google.com>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	young.liuyang@huawei.com, zengweilin@huawei.com, chenzefeng2@huawei.com, 
	nixiaoming@huawei.com, wangbing6@huawei.com, wangfangpeng1@huawei.com, 
	zhongjubin@huawei.com
Content-Type: multipart/alternative; boundary="0000000000005b4af005dd273ce1"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ocgx+hoZ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b30 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

--0000000000005b4af005dd273ce1
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Apr 20, 2022 at 12:50 PM Shaobo Huang <huangshaobo6@huawei.com>
wrote:

> From: huangshaobo <huangshaobo6@huawei.com>
>
> when writing out of bounds to the red zone, it can only be detected at
> kfree. However, there were many scenarios before kfree that caused this
> out-of-bounds write to not be detected. Therefore, it is necessary to
> provide a method for actively detecting out-of-bounds writing to the red
> zone, so that users can actively detect, and can be detected in the
> system reboot or panic.
>
>
After having analyzed a couple of KFENCE memory corruption reports in the
wild, I have doubts that this approach will be helpful.

Note that KFENCE knows nothing about the memory access that performs the
actual corruption.

It's rather easy to investigate corruptions of short-living objects, e.g.
those that are allocated and freed within the same function. In that case,
one can examine the region of the code between these two events and try to
understand what exactly caused the corruption.

But for long-living objects checked at panic/reboot we'll effectively have
only the allocation stack and will have to check all the places where the
corrupted object was potentially used.
Most of the time, such reports won't be actionable.


> for example, if the application memory is out of bounds and written to
> the red zone in the kfence object, the system suddenly panics, and the
> following log can be seen during system reset:
> BUG: KFENCE: memory corruption in atomic_notifier_call_chain+0x49/0x70
>
> Corrupted memory at 0x(____ptrval____) [ ! ] (in kfence-#59):
>  atomic_notifier_call_chain+0x49/0x70
>  panic+0x134/0x278
>  sysrq_handle_crash+0x11/0x20
>  __handle_sysrq+0x99/0x160
>  write_sysrq_trigger+0x26/0x30
>  proc_reg_write+0x51/0x70
>  vfs_write+0xb6/0x290
>  ksys_write+0x9c/0xd0
>  __do_fast_syscall_32+0x67/0xe0
>  do_fast_syscall_32+0x2f/0x70
>  entry_SYSCALL_compat_after_hwframe+0x45/0x4d
>
> kfence-#59:
> 0x(____ptrval____)-0x(____ptrval____),size=3D100,cache=3Dkmalloc-128
>  allocated by task 77 on cpu 0 at 28.018073s:
>  0xffffffffc007703d
>  do_one_initcall+0x3c/0x1e0
>  do_init_module+0x46/0x1d8
>  load_module+0x2397/0x2860
>  __do_sys_init_module+0x160/0x190
>  __do_fast_syscall_32+0x67/0xe0
>  do_fast_syscall_32+0x2f/0x70
>  entry_SYSCALL_compat_after_hwframe+0x45/0x4d
>
> Suggested-by: chenzefeng <chenzefeng2@huawei.com>
> Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
> ---
>  mm/kfence/core.c | 28 ++++++++++++++++++++++++++++
>  1 file changed, 28 insertions(+)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 9b2b5f56f4ae..85cc3ca4b71c 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -29,6 +29,9 @@
>  #include <linux/slab.h>
>  #include <linux/spinlock.h>
>  #include <linux/string.h>
> +#include <linux/notifier.h>
> +#include <linux/reboot.h>
> +#include <linux/panic_notifier.h>
>
>  #include <asm/kfence.h>
>
> @@ -716,6 +719,29 @@ static const struct file_operations objects_fops =3D=
 {
>         .release =3D seq_release,
>  };
>
> +static void kfence_check_all_canary(void)
> +{
> +       int i;
> +
> +       for (i =3D 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> +               struct kfence_metadata *meta =3D &kfence_metadata[i];
> +
> +               if (meta->state =3D=3D KFENCE_OBJECT_ALLOCATED)
> +                       for_each_canary(meta, check_canary_byte);
> +       }
> +}
> +
> +static int kfence_check_canary_callback(struct notifier_block *nb,
> +                                       unsigned long reason, void *arg)
> +{
> +       kfence_check_all_canary();
> +       return NOTIFY_OK;
> +}
> +
> +static struct notifier_block kfence_check_canary_notifier =3D {
> +       .notifier_call =3D kfence_check_canary_callback,
> +};
> +
>  static int __init kfence_debugfs_init(void)
>  {
>         struct dentry *kfence_dir =3D debugfs_create_dir("kfence", NULL);
> @@ -806,6 +832,8 @@ static void kfence_init_enable(void)
>
>         WRITE_ONCE(kfence_enabled, true);
>         queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> +       register_reboot_notifier(&kfence_check_canary_notifier);
> +       atomic_notifier_chain_register(&panic_notifier_list,
> &kfence_check_canary_notifier);
>
>         pr_info("initialized - using %lu bytes for %d objects at
> 0x%p-0x%p\n", KFENCE_POOL_SIZE,
>                 CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
> --
> 2.12.3
>
>

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise erhalt=
en
haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich bit=
te wissen,
dass die E-Mail an die falsche Person gesendet wurde.


This e-mail is confidential. If you received this communication by mistake,
please don't forward it to anyone else, please erase all copies and
attachments, and please let me know that it has gone to the wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXs-OqpVCW5KyQLYKXNmQ4aH-KDjY0BrWpqMfPKcu-dug%40mail.gmai=
l.com.

--0000000000005b4af005dd273ce1
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Wed, Apr 20, 2022 at 12:50 PM Shao=
bo Huang &lt;<a href=3D"mailto:huangshaobo6@huawei.com">huangshaobo6@huawei=
.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"mar=
gin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1=
ex">From: huangshaobo &lt;<a href=3D"mailto:huangshaobo6@huawei.com" target=
=3D"_blank">huangshaobo6@huawei.com</a>&gt;<br>
<br>
when writing out of bounds to the red zone, it can only be detected at<br>
kfree. However, there were many scenarios before kfree that caused this<br>
out-of-bounds write to not be detected. Therefore, it is necessary to<br>
provide a method for actively detecting out-of-bounds writing to the red<br=
>
zone, so that users can actively detect, and can be detected in the<br>
system reboot or panic.<br>
<br></blockquote><div><br></div><div>After having analyzed a couple of KFEN=
CE memory corruption reports in the wild, I have doubts that this approach =
will be helpful.<div><br></div><div>Note that KFENCE knows nothing about th=
e memory access that performs the actual corruption.</div><div><br></div><d=
iv>It&#39;s rather easy to investigate corruptions of short-living objects,=
 e.g. those that are allocated and freed within the same function. In that =
case, one can examine the region of the code between these two events and t=
ry to understand what exactly caused the corruption.</div><div><br></div><d=
iv>But for long-living objects checked at panic/reboot we&#39;ll effectivel=
y have only the allocation stack and will have to check all the places wher=
e the corrupted object was potentially used.</div><div>Most of the time, su=
ch reports won&#39;t be actionable.</div></div><div>=C2=A0</div><blockquote=
 class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px so=
lid rgb(204,204,204);padding-left:1ex">
for example, if the application memory is out of bounds and written to<br>
the red zone in the kfence object, the system suddenly panics, and the<br>
following log can be seen during system reset:<br>
BUG: KFENCE: memory corruption in atomic_notifier_call_chain+0x49/0x70<br>
<br>
Corrupted memory at 0x(____ptrval____) [ ! ] (in kfence-#59):<br>
=C2=A0atomic_notifier_call_chain+0x49/0x70<br>
=C2=A0panic+0x134/0x278<br>
=C2=A0sysrq_handle_crash+0x11/0x20<br>
=C2=A0__handle_sysrq+0x99/0x160<br>
=C2=A0write_sysrq_trigger+0x26/0x30<br>
=C2=A0proc_reg_write+0x51/0x70<br>
=C2=A0vfs_write+0xb6/0x290<br>
=C2=A0ksys_write+0x9c/0xd0<br>
=C2=A0__do_fast_syscall_32+0x67/0xe0<br>
=C2=A0do_fast_syscall_32+0x2f/0x70<br>
=C2=A0entry_SYSCALL_compat_after_hwframe+0x45/0x4d<br>
<br>
kfence-#59: 0x(____ptrval____)-0x(____ptrval____),size=3D100,cache=3Dkmallo=
c-128<br>
=C2=A0allocated by task 77 on cpu 0 at 28.018073s:<br>
=C2=A00xffffffffc007703d<br>
=C2=A0do_one_initcall+0x3c/0x1e0<br>
=C2=A0do_init_module+0x46/0x1d8<br>
=C2=A0load_module+0x2397/0x2860<br>
=C2=A0__do_sys_init_module+0x160/0x190<br>
=C2=A0__do_fast_syscall_32+0x67/0xe0<br>
=C2=A0do_fast_syscall_32+0x2f/0x70<br>
=C2=A0entry_SYSCALL_compat_after_hwframe+0x45/0x4d<br>
<br>
Suggested-by: chenzefeng &lt;<a href=3D"mailto:chenzefeng2@huawei.com" targ=
et=3D"_blank">chenzefeng2@huawei.com</a>&gt;<br>
Signed-off-by: huangshaobo &lt;<a href=3D"mailto:huangshaobo6@huawei.com" t=
arget=3D"_blank">huangshaobo6@huawei.com</a>&gt;<br>
---<br>
=C2=A0mm/kfence/core.c | 28 ++++++++++++++++++++++++++++<br>
=C2=A01 file changed, 28 insertions(+)<br>
<br>
diff --git a/mm/kfence/core.c b/mm/kfence/core.c<br>
index 9b2b5f56f4ae..85cc3ca4b71c 100644<br>
--- a/mm/kfence/core.c<br>
+++ b/mm/kfence/core.c<br>
@@ -29,6 +29,9 @@<br>
=C2=A0#include &lt;linux/slab.h&gt;<br>
=C2=A0#include &lt;linux/spinlock.h&gt;<br>
=C2=A0#include &lt;linux/string.h&gt;<br>
+#include &lt;linux/notifier.h&gt;<br>
+#include &lt;linux/reboot.h&gt;<br>
+#include &lt;linux/panic_notifier.h&gt;<br>
<br>
=C2=A0#include &lt;asm/kfence.h&gt;<br>
<br>
@@ -716,6 +719,29 @@ static const struct file_operations objects_fops =3D {=
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 .release =3D seq_release,<br>
=C2=A0};<br>
<br>
+static void kfence_check_all_canary(void)<br>
+{<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0int i;<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0for (i =3D 0; i &lt; CONFIG_KFENCE_NUM_OBJECTS;=
 i++) {<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0struct kfence_metad=
ata *meta =3D &amp;kfence_metadata[i];<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (meta-&gt;state =
=3D=3D KFENCE_OBJECT_ALLOCATED)<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0for_each_canary(meta, check_canary_byte);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0}<br>
+}<br>
+<br>
+static int kfence_check_canary_callback(struct notifier_block *nb,<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0unsigned =
long reason, void *arg)<br>
+{<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0kfence_check_all_canary();<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0return NOTIFY_OK;<br>
+}<br>
+<br>
+static struct notifier_block kfence_check_canary_notifier =3D {<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0.notifier_call =3D kfence_check_canary_callback=
,<br>
+};<br>
+<br>
=C2=A0static int __init kfence_debugfs_init(void)<br>
=C2=A0{<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 struct dentry *kfence_dir =3D debugfs_create_di=
r(&quot;kfence&quot;, NULL);<br>
@@ -806,6 +832,8 @@ static void kfence_init_enable(void)<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 WRITE_ONCE(kfence_enabled, true);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 queue_delayed_work(system_unbound_wq, &amp;kfen=
ce_timer, 0);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0register_reboot_notifier(&amp;kfence_check_cana=
ry_notifier);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0atomic_notifier_chain_register(&amp;panic_notif=
ier_list, &amp;kfence_check_canary_notifier);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_info(&quot;initialized - using %lu bytes for=
 %d objects at 0x%p-0x%p\n&quot;, KFENCE_POOL_SIZE,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 CONFIG_KFENCE_NUM_O=
BJECTS, (void *)__kfence_pool,<br>
-- <br>
2.12.3<br>
<br>
</blockquote></div><br clear=3D"all"><div><br></div>-- <br><div dir=3D"ltr"=
 class=3D"gmail_signature"><div dir=3D"ltr">Alexander Potapenko<br>Software=
 Engineer<br><br>Google Germany GmbH<br>Erika-Mann-Stra=C3=9Fe, 33<br>80636=
 M=C3=BCnchen<br><br>Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebasti=
an<br>Registergericht und -nummer: Hamburg, HRB 86891<br>Sitz der Gesellsch=
aft: Hamburg<br><br>Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4ls=
chlicherweise erhalten haben sollten, leiten Sie diese bitte nicht an jeman=
d anderes weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und l=
assen Sie mich bitte wissen, dass die E-Mail an die falsche Person gesendet=
 wurde.<br><br><br>This e-mail is confidential. If you received this commun=
ication by mistake, please don&#39;t forward it to anyone else, please eras=
e all copies and attachments, and please let me know that it has gone to th=
e wrong person.</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DXs-OqpVCW5KyQLYKXNmQ4aH-KDjY0BrWpqMfPKcu-dug%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DXs-OqpVCW5KyQLYKXNmQ4aH-KDjY0BrWpqMfPKcu=
-dug%40mail.gmail.com</a>.<br />

--0000000000005b4af005dd273ce1--
