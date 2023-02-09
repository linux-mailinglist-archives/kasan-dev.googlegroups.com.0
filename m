Return-Path: <kasan-dev+bncBCMIZB7QWENRBHE5SOPQMGQEUZJTDKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 688B469056C
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 11:44:45 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id gz8-20020a170907a04800b0087bd94a505fsf1252578ejc.16
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 02:44:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675939485; cv=pass;
        d=google.com; s=arc-20160816;
        b=yWICEEb+78vB/POFHm34rsSQCDSYnf98MI7e8xS0O0Tm10ky0i0fOl5QEW4U+mwaqo
         W7Mo9oES3bbekQF6fOKSU3pmuuR0/y7DNeXiwmLE+FKsIiFjyUwFBb7boOw7k2i+AYC2
         AhRhLpt4cw1j2i3an2al+DVOS7aD20IqJScRkU3BWVZRRUw0m3l+X4So8KHZJ3knxmUI
         lTTlS0H9UMR4rDOGW4RYIkz0HFtQOxGeT7wMYCDnAvYoeY/uqfg/9oSo1Bj6VqhGmCkI
         EImf95MZ3PeABvBTqFLUPB2voV07EsBBwUcWF1ZzeLPYLKyxpdMNVHiJIs5YUyKBLhXb
         Yveg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=joaCmAinZPOoEbLNuSwwniFoT4BVeyIyTJyleeY18YQ=;
        b=jjmdJMScpdnTYLKOh5QaFHl91EvfDRhLsbIThQ6jeHocQp/M+gwMT4byeVicv5a6S6
         CGKipg2p7TX/hIWcuXqYRll4Dym6eUReoH7/S7qktpajzkMPri2cBQ6hD9Vv/DC4L2rR
         DcUg8OJ4qciAIalNV9iQzTOAcYt1Gz8B+vp30cotJAtWCQMD9dmpkVXDHgBhFFb1vbaG
         gtyJK/jFUIcsf+IEQ4PNcunXE6tahvA2mQ0X3lGJDC8CNKlR6ma7EfrdV+pmonSoSB7N
         bdmqQ2zK7/HGkFYzwi2rOE0DPF4w66ZrgSVNEH1HyVdyX7X8AVu4mlwodNVJxpJmXTxh
         NmUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UGzZPXcJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=joaCmAinZPOoEbLNuSwwniFoT4BVeyIyTJyleeY18YQ=;
        b=Whlaq4agJCFE0LII3/JQYSyiwexwko8lDhEukysJ5bdPwegTN7bl9IVFuzZnukd2Du
         00ZZIvVGQ8+NSUT9GSeobE24mFww+xwR1/qMSAMRvxc7dQk1fedfnkDclRLVUVSB8J+R
         kOLIghI7okPq8JxtIcEZWcP0+CKPILifxhrAT2ZBBpu80C3WZ1foH1+ZDs1QGPKhQt4j
         VgP0peG4CBvT4G4uMBYLJBiNAUhkwR+GVIJDwJILhVhiwBO88/QZqMInS7cq0EHlrxAz
         wW6tmNonjST1/08lIHTbb+V/OPCH5gnGuNBCROQMItHfFjMN95dZFZkhLNzauhtz7FH9
         VNhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=joaCmAinZPOoEbLNuSwwniFoT4BVeyIyTJyleeY18YQ=;
        b=3sjgmMNhO/H2tic/KFJNdIWe87KBTV2lJ9J8s+Ym3e5BZI7HegzApIAnEmGuwwNuym
         TSekQQ0mk6hck3dnuadxU6mzJiLbtvW+ny0/DIQjX9JCIwwPiNlQxjvODjy5HV8UO9DS
         ESOoJh/LY3ylef5da73nWAtCoAdSJ/lfqFaP/Y3MIhRqZzBxcAEz8hX5UbwVEvR8G1Z6
         F62ru1m+4QFbFMiUhlIkBG8fNeLp+KTSjrqc396SjhijU+vKaLjTVeJPZUqwr0hm1REN
         E+wgZIeLGYBMvpbSG2XiGD7J1KDqDdrIxgIzc6akLZrX2RYdi+0hct0oDkylad5sTmSA
         z2jg==
X-Gm-Message-State: AO0yUKUjdPtQhydg12d4WUCv+5tx5u1ppG1hbi+IbjB/Kg1c03VTHlYl
	Tgp6/NRPzmELLm+TXQeJQZE=
X-Google-Smtp-Source: AK7set/2vf2zvmhNxFMvEkdDLzdTdg+1a9osl9RoF3HqiPJry7MMhEm50xxUv+XBHDrT2ao5xU/cBg==
X-Received: by 2002:a17:906:6991:b0:878:4e40:d3e0 with SMTP id i17-20020a170906699100b008784e40d3e0mr408287ejr.13.1675939485001;
        Thu, 09 Feb 2023 02:44:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3c7:b0:878:509e:727f with SMTP id
 c7-20020a17090603c700b00878509e727fls1088105eja.11.-pod-prod-gmail; Thu, 09
 Feb 2023 02:44:43 -0800 (PST)
X-Received: by 2002:a17:906:d0c4:b0:88d:5043:2299 with SMTP id bq4-20020a170906d0c400b0088d50432299mr11179386ejb.51.1675939483710;
        Thu, 09 Feb 2023 02:44:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675939483; cv=none;
        d=google.com; s=arc-20160816;
        b=UzUiOwskqyMFSIpRgj5/DgEvAZvbE2v5GmsGyjMg8A2OkB9Lq3US7vh/TCakzhpNQI
         JleQq1UXPEZczlNLIeVLtjGcoa08ImO83taHyIU88humEx7QLdHYJk7jIHX66E7DbJkP
         Z3Lcdb4Urt4JIg8aEIdkp2L604BBl0lyqgyecYZrokEww3Hcc9M0Wfir7gBNDn2gHZP8
         mqkrG44scLusSVNVPbwbd15p+9sVO3+lbXtmMWnBYRDJCpew+BqJswLTUWZKk9pYWn3Q
         DrJy8CfxraOZLxFFul4rgVSz3NI0TzIK9n/Sepq/q4tEJogcLgeZ3VuI7Za84xolVzlI
         +v2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RI6fqWlX5YUhT5J0Rtyo4N3gfV1eJtvT1+AvPfJcUdg=;
        b=Uho8hBf+f8EX4JAG/DiB9nG+WUlKFMIPHCuFv3nvbxZkGLXYbwaeWWfURtUN2lcuBV
         CbWlozwfyE3VemFbywkWay8VF+FbmssHRq3WMnFU9paUoZ6Ljv9R+xXkapQ21FKM9WkF
         OEXiQ0idvS+qQ9AsTbYPPcaKFCsyd5np0ti07noEZQZ8eNV2Q95veu7d+yxd8Ms/8g/Y
         qBXUNpT9vIMVWiAuAa05ajMIfu/4BQgCybHQaRhYPOvaiMoNlQXb7bBgAToEkw51s4QJ
         GierQCNkD99gDc+J17+eBmNY/S5ZZqlwcKnWfWfYUexFUCJUtWyxaXwDEAnOpzLz4DJT
         4LYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UGzZPXcJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id i19-20020a170906251300b0087873f29192si69218ejb.2.2023.02.09.02.44.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Feb 2023 02:44:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id j17so2616672lfr.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Feb 2023 02:44:43 -0800 (PST)
X-Received: by 2002:ac2:51c7:0:b0:4d5:86a8:55d1 with SMTP id
 u7-20020ac251c7000000b004d586a855d1mr1805227lfm.155.1675939482991; Thu, 09
 Feb 2023 02:44:42 -0800 (PST)
MIME-Version: 1.0
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com> <93b94f59016145adbb1e01311a1103f8@zeku.com>
In-Reply-To: <93b94f59016145adbb1e01311a1103f8@zeku.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Feb 2023 11:44:30 +0100
Message-ID: <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix deadlock in start_report()
To: =?UTF-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>
Cc: =?UTF-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?= <ouyangweizhao@zeku.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Weizhao Ouyang <o451686892@gmail.com>, 
	=?UTF-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?= <renlipeng@zeku.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UGzZPXcJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133
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

 aOn Thu, 9 Feb 2023 at 10:19, =E8=A2=81=E5=B8=85(Shuai Yuan) <yuanshuai@ze=
ku.com> wrote:
>
> Hi Dmitry Vyukov
>
> Thanks, I see that your means.
>
> Currently, report_suppressed() seem not work in Kasan-HW mode, it always =
return false.
> Do you think should change the report_suppressed function?
> I don't know why CONFIG_KASAN_HW_TAGS was blocked separately before.

That logic was added by Andrey in:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?=
id=3Dc068664c97c7cf

Andrey, can we make report_enabled() check current->kasan_depth and
remove report_suppressed()?

Then we can also remove the comment in kasan_report_invalid_free().

It looks like kasan_disable_current() in kmemleak needs to affect
HW_TAGS mode as well:
https://elixir.bootlin.com/linux/v6.2-rc7/source/mm/kmemleak.c#L301

So overall it looks like simplifications and it will fix what Shuai reporte=
d.




> -----=E9=82=AE=E4=BB=B6=E5=8E=9F=E4=BB=B6-----
> =E5=8F=91=E4=BB=B6=E4=BA=BA: Dmitry Vyukov <dvyukov@google.com>
> =E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2023=E5=B9=B42=E6=9C=889=E6=97=A5 1=
6:56
> =E6=94=B6=E4=BB=B6=E4=BA=BA: =E6=AC=A7=E9=98=B3=E7=82=9C=E9=92=8A(Weizhao=
 Ouyang) <ouyangweizhao@zeku.com>
> =E6=8A=84=E9=80=81: Andrey Ryabinin <ryabinin.a.a@gmail.com>; Alexander P=
otapenko <glider@google.com>; Andrey Konovalov <andreyknvl@gmail.com>; Vinc=
enzo Frascino <vincenzo.frascino@arm.com>; Andrew Morton <akpm@linux-founda=
tion.org>; kasan-dev@googlegroups.com; linux-mm@kvack.org; linux-kernel@vge=
r.kernel.org; Weizhao Ouyang <o451686892@gmail.com>; =E8=A2=81=E5=B8=85(Shu=
ai Yuan) <yuanshuai@zeku.com>; =E4=BB=BB=E7=AB=8B=E9=B9=8F(Peng Ren) <renli=
peng@zeku.com>
> =E4=B8=BB=E9=A2=98: Re: [PATCH v2] kasan: fix deadlock in start_report()
>
> On Thu, 9 Feb 2023 at 04:27, Weizhao Ouyang <ouyangweizhao@zeku.com> wrot=
e:
> >
> > From: Weizhao Ouyang <o451686892@gmail.com>
> >
> > From: Shuai Yuan <yuanshuai@zeku.com>
> >
> > Calling start_report() again between start_report() and end_report()
> > will result in a race issue for the report_lock. In extreme cases this
> > problem arose in Kunit tests in the hardware tag-based Kasan mode.
> >
> > For example, when an invalid memory release problem is found,
> > kasan_report_invalid_free() will print error log, but if an MTE
> > exception is raised during the output log, the kasan_report() is
> > called, resulting in a deadlock problem. The kasan_depth not protect
> > it in hardware tag-based Kasan mode.
>
> I think checking report_suppressed() would be cleaner and simpler than ig=
noring all trylock failures. If trylock fails, it does not mean that the cu=
rrent thread is holding it. We of course could do a custom lock which store=
s current->tid in the lock word, but it looks effectively equivalent to che=
cking report_suppressed().
>
>
>
> > Signed-off-by: Shuai Yuan <yuanshuai@zeku.com>
> > Reviewed-by: Weizhao Ouyang <ouyangweizhao@zeku.com>
> > Reviewed-by: Peng Ren <renlipeng@zeku.com>
> > ---
> > Changes in v2:
> > -- remove redundant log
> >
> >  mm/kasan/report.c | 25 ++++++++++++++++++++-----
> >  1 file changed, 20 insertions(+), 5 deletions(-)
> >
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c index
> > 22598b20c7b7..aa39aa8b1855 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -166,7 +166,7 @@ static inline void fail_non_kasan_kunit_test(void)
> > { }
> >
> >  static DEFINE_SPINLOCK(report_lock);
> >
> > -static void start_report(unsigned long *flags, bool sync)
> > +static bool start_report(unsigned long *flags, bool sync)
> >  {
> >         fail_non_kasan_kunit_test();
> >         /* Respect the /proc/sys/kernel/traceoff_on_warning interface.
> > */ @@ -175,8 +175,13 @@ static void start_report(unsigned long *flags, =
bool sync)
> >         lockdep_off();
> >         /* Make sure we don't end up in loop. */
> >         kasan_disable_current();
> > -       spin_lock_irqsave(&report_lock, *flags);
> > +       if (!spin_trylock_irqsave(&report_lock, *flags)) {
> > +               lockdep_on();
> > +               kasan_enable_current();
> > +               return false;
> > +       }
> >
> > pr_err("=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > =3D=3D=3D=3D\n");
> > +       return true;
> >  }
> >
> >  static void end_report(unsigned long *flags, void *addr) @@ -468,7
> > +473,10 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, =
enum kasan_report_ty
> >         if (unlikely(!report_enabled()))
> >                 return;
> >
> > -       start_report(&flags, true);
> > +       if (!start_report(&flags, true)) {
> > +               pr_err("%s: report ignore\n", __func__);
> > +               return;
> > +       }
> >
> >         memset(&info, 0, sizeof(info));
> >         info.type =3D type;
> > @@ -503,7 +511,11 @@ bool kasan_report(unsigned long addr, size_t size,=
 bool is_write,
> >                 goto out;
> >         }
> >
> > -       start_report(&irq_flags, true);
> > +       if (!start_report(&irq_flags, true)) {
> > +               ret =3D false;
> > +               pr_err("%s: report ignore\n", __func__);
> > +               goto out;
> > +       }
> >
> >         memset(&info, 0, sizeof(info));
> >         info.type =3D KASAN_REPORT_ACCESS; @@ -536,7 +548,10 @@ void
> > kasan_report_async(void)
> >         if (unlikely(!report_enabled()))
> >                 return;
> >
> > -       start_report(&flags, false);
> > +       if (!start_report(&flags, false)) {
> > +               pr_err("%s: report ignore\n", __func__);
> > +               return;
> > +       }
> >         pr_err("BUG: KASAN: invalid-access\n");
> >         pr_err("Asynchronous fault: no details available\n");
> >         pr_err("\n");
> > --
> > 2.25.1
> >
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/20230209031159.2337445-1-ouyangweizhao%40zeku.com.
> ZEKU
> =E4=BF=A1=E6=81=AF=E5=AE=89=E5=85=A8=E5=A3=B0=E6=98=8E=EF=BC=9A=E6=9C=AC=
=E9=82=AE=E4=BB=B6=E5=8C=85=E5=90=AB=E4=BF=A1=E6=81=AF=E5=BD=92=E5=8F=91=E4=
=BB=B6=E4=BA=BA=E6=89=80=E5=9C=A8=E7=BB=84=E7=BB=87ZEKU=E6=89=80=E6=9C=89=
=E3=80=82 =E7=A6=81=E6=AD=A2=E4=BB=BB=E4=BD=95=E4=BA=BA=E5=9C=A8=E6=9C=AA=
=E7=BB=8F=E6=8E=88=E6=9D=83=E7=9A=84=E6=83=85=E5=86=B5=E4=B8=8B=E4=BB=A5=E4=
=BB=BB=E4=BD=95=E5=BD=A2=E5=BC=8F=EF=BC=88=E5=8C=85=E6=8B=AC=E4=BD=86=E4=B8=
=8D=E9=99=90=E4=BA=8E=E5=85=A8=E9=83=A8=E6=88=96=E9=83=A8=E5=88=86=E6=8A=AB=
=E9=9C=B2=E3=80=81=E5=A4=8D=E5=88=B6=E6=88=96=E4=BC=A0=E6=92=AD=EF=BC=89=E4=
=BD=BF=E7=94=A8=E5=8C=85=E5=90=AB=E7=9A=84=E4=BF=A1=E6=81=AF=E3=80=82=E8=8B=
=A5=E6=82=A8=E9=94=99=E6=94=B6=E4=BA=86=E6=9C=AC=E9=82=AE=E4=BB=B6=EF=BC=8C=
=E8=AF=B7=E7=AB=8B=E5=8D=B3=E7=94=B5=E8=AF=9D=E6=88=96=E9=82=AE=E4=BB=B6=E9=
=80=9A=E7=9F=A5=E5=8F=91=E4=BB=B6=E4=BA=BA=EF=BC=8C=E5=B9=B6=E5=88=A0=E9=99=
=A4=E6=9C=AC=E9=82=AE=E4=BB=B6=E5=8F=8A=E9=99=84=E4=BB=B6=E3=80=82
> Information Security Notice: The information contained in this mail is so=
lely property of the sender's organization ZEKU. Any use of the information=
 contained herein in any way (including, but not limited to, total or parti=
al disclosure, reproduction, or dissemination) by persons other than the in=
tended recipient(s) is prohibited. If you receive this email in error, plea=
se notify the sender by phone or email immediately and delete it.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Ba%3DBaMNUf%3D_suQ5or9%3DZksX2ht9gX8%3DXBSDEgHogyy3mg%40m=
ail.gmail.com.
