Return-Path: <kasan-dev+bncBCJZRXGY5YJBBLFAROEAMGQEY63OK5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B29D3DA81F
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 17:58:37 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id b32-20020a4a98e30000b029026222bb0380sf2369317ooj.23
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 08:58:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627574316; cv=pass;
        d=google.com; s=arc-20160816;
        b=CsS6VLs+HgpEtlCG7E5UbB40xu9ZS6cHgp+onJm/iXEyhAZ/2Rt5VXAAADOT2dudAo
         2OVUW1xL6iK6ObfNcwucJX74Cv2Zz2FOijghDCl2V8XGzuIuUojPbQIs5abpp+pXNps0
         iZMFnadrcsSsfwWKInRKbJACNgcMnLAm+9bri9SNzbWRYhXlBHgCv/6TWN4+zMmPesbK
         6DTMjD3LAKGsMo6WyOePfpZCdxKqXkM5maxyyp7K28uSO5h5KzICBAi9Mkerz/nH8hEu
         ubobLhKEf1lQuGT+mnp3mDvmMZr7NVUitoo8Y7+jGEcU0g/6wXq/xHDABTk8avLeCshk
         W8zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wC51Oj70YYvjffnPD5QURJJJCxfGy85eexR78Cbh7ug=;
        b=RlfZgriEjSjkco3LdgEGtK1dmx3071pgR4R+lSc5WLd7wuRiqvZJw0dn3/gMfvis2P
         f89l3WRkOIkmL46LOu/A/26kiaC0ZSUEO0vfeOI0XrV5ZKD7+deStOtnNze0lGye2hVO
         GZKgmwE4aQGwjJrOJCzogPqHPuNAlx3APoYio/LMd+dPdxFXrH8nNTULsdtc5z6CNYxK
         xIAGCFYPXAx+cuq4PE8x/FsAyaTsezkKmljY/4JLSM1xtORo1anCy2HoFPxoT+WNUQpR
         RR9+6MKYV1iRAO4iWWdiORo1xwn0yB6iACyYU04+LQYkCed9UAcon/5hYcLH0Q/DiZTI
         +oaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=coG04a+n;
       spf=pass (google.com: domain of srs0=zgbf=mv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZgBF=MV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wC51Oj70YYvjffnPD5QURJJJCxfGy85eexR78Cbh7ug=;
        b=GvkIaCXBkFiEtSnW1atbFKnopH8j8OmfuUL+laRqskzGF3EM24yxdK+ynnHn/Cmt1E
         AuX5BXI5re8dYJaNoPEi0prwVmmLaNNsh1Zd+vVPojuxnN1Yt3/kK1J0aGF29JhoTKFg
         zhPTHpX9akyZA3u8urMVvHMNHImonw36DrBFcSKxbdNmwHyLFK7dXXC9V2JGCPg8TvyI
         gT7sh+8HatERfwtl/1tWHSE81SWDgYl8bYKPGXWtDpfZ2WONrFCh7DEkA9fuWKuSiIqO
         FJFLe2BPpYp179pxFxfA/W2P4TJEBTyLn4fsO/2my1d7zEZvnkGw+w6yNTbCcEs6mQkM
         90uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wC51Oj70YYvjffnPD5QURJJJCxfGy85eexR78Cbh7ug=;
        b=GCy5xMJtLBJ1PgJnk0kdtqWSRJU0sW3AfNHAMpHfdmv3z2JXtEAIgctSVqaj7SFmld
         XV/Vtj5j8Q+GnOgI8oMWkkSlipyqruwY/NHwG9+mceDW3A74ge80h5bPi2S31TAc1Kkd
         dRmOqhqaGu3R/iTOFelr1OUfAVX7R9r1f7D5ujSoq1IPTuYNvKP8X5/V3wrVcy+4Vte0
         cPEN5Jahtl5M33hv8ZxGWp88+1ya5ywZL+FH6ohTMpHJj033BMSD2JuLylOswMyiRjKn
         4DtVAFN3OaoNpOuatU+pG0uuGG5wz2mHNS4QTlVF8GN1I+9zUt1iIdHZsJLpGY7PUeDI
         l0yg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LSZupqf5F5m08xbnnry9KKwoKaGkmSrO3aTF+/gQLSVfta4HV
	3lgv5ZHrpxmj9nXdpIVfIAo=
X-Google-Smtp-Source: ABdhPJyuH5b7JzQ70BJrndkpHwmOPSP3237Tsu4e784xi5T/9gzt/PcmzqwBbSHCxLGqQaEodDHyiw==
X-Received: by 2002:aca:654d:: with SMTP id j13mr10849385oiw.113.1627574316259;
        Thu, 29 Jul 2021 08:58:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3115:: with SMTP id b21ls1540449ots.4.gmail; Thu,
 29 Jul 2021 08:58:35 -0700 (PDT)
X-Received: by 2002:a9d:75d8:: with SMTP id c24mr3991508otl.109.1627574315905;
        Thu, 29 Jul 2021 08:58:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627574315; cv=none;
        d=google.com; s=arc-20160816;
        b=g5rZ4hwkXSNjXqcHompYmDhIJ0DVT0bqZiq8p20H1Ge6LeQrSGNlb4ZIdDYBJMrLIc
         5Hp2I3HQOC8yecXBLo4GUMhmL3625DngY2XJyrLD276axSxczkRgX2y3lzY0NJhYKogX
         yW37SxBjL0WWmg+lpiAW6DnJzCZ/Zfxtrrv4fnGV9qgDTJ6l664aw45/v26Mxjomr7+M
         toX4Vz/PXXmg8AOkQejTZNKwrJCf22O+3n7dOE7fzmxvyyt/czjZprd3P/8ywu8H7Vqw
         Fzz1yU/qjlv35apFuR15FJs1FYXHncK+shNOKGA8RDvttkOZODqDutJ0H9DwSl7y02Zo
         rR5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=thpflaunPfpZl8ZBuTa3MkLmU7iNp7YnzzPhpwELtdQ=;
        b=n+HR0ebGumTqnRJvETK0s3haX/Uv59r77/5oUqHgc3XpGyzkhnYZ+6+VCxChBbqhsx
         CNIaRB0KVA1NE/z8kXayWEvXqhar4dylEzsPLMDBKnXvQ+MqMeTTK/ukuZ0ZaWRWjGjf
         ts5qLJ+GX7LvSw+qPpQf8+Y3LknH2zJ391DeUUfoqPbsIZAQGXtysZPbGPbFVhIIvijr
         1SGJ9UmRvDDnzIE5dCa6/r1MxpslwnJK7+hqlsDw0LWs1/wkBtARk0gtyfE4sBOzYpLV
         b77J254vzI1vVmDP2gLRYPJV3gNnqo8zRi3PKl97HCD6nAQqoQtE8ZCqjjjkU0bnKF+X
         FyoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=coG04a+n;
       spf=pass (google.com: domain of srs0=zgbf=mv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZgBF=MV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l23si226554otb.2.2021.07.29.08.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 29 Jul 2021 08:58:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zgbf=mv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1AC2860F21;
	Thu, 29 Jul 2021 15:58:35 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id DD6755C04E6; Thu, 29 Jul 2021 08:58:34 -0700 (PDT)
Date: Thu, 29 Jul 2021 08:58:34 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: Re: [PATCH] kcsan: use u64 instead of cycles_t
Message-ID: <20210729155834.GX4397@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210729142811.1309391-1-hca@linux.ibm.com>
 <CANpmjNM=rSFwmJCEq6gxHZBdYKVZas4rbnd2gk8GCAEjiJ_5UQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNM=rSFwmJCEq6gxHZBdYKVZas4rbnd2gk8GCAEjiJ_5UQ@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=coG04a+n;       spf=pass
 (google.com: domain of srs0=zgbf=mv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZgBF=MV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, Jul 29, 2021 at 04:53:10PM +0200, Marco Elver wrote:
> +Cc: Paul
>=20
> On Thu, 29 Jul 2021 at 16:28, Heiko Carstens <hca@linux.ibm.com> wrote:
> >
> > cycles_t has a different type across architectures: unsigned int,
> > unsinged long, or unsigned long long. Depending on architecture this
> > will generate this warning:
> >
> > kernel/kcsan/debugfs.c: In function =E2=80=98microbenchmark=E2=80=99:
> > ./include/linux/kern_levels.h:5:25: warning: format =E2=80=98%llu=E2=80=
=99 expects argument of type =E2=80=98long long unsigned int=E2=80=99, but =
argument 3 has type =E2=80=98cycles_t=E2=80=99 {aka =E2=80=98long unsigned =
int=E2=80=99} [-Wformat=3D]
> >
> > To avoid this simple change the type of cycle to u64 in
> > microbenchmark(), since u64 is of type unsigned long long for all
> > architectures.
> >
> > Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
>=20
> Acked-by: Marco Elver <elver@google.com>
>=20
> Do you have a series adding KCSAN support for s390, i.e. would you
> like to keep it together with those changes?
>=20
> Otherwise this would go the usual route through Paul's -rcu tree.

Either way, please let me know!

							Thanx, Paul

> Thanks,
> -- Marco
>=20
> > ---
> >  kernel/kcsan/debugfs.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> > index e65de172ccf7..1d1d1b0e4248 100644
> > --- a/kernel/kcsan/debugfs.c
> > +++ b/kernel/kcsan/debugfs.c
> > @@ -64,7 +64,7 @@ static noinline void microbenchmark(unsigned long ite=
rs)
> >  {
> >         const struct kcsan_ctx ctx_save =3D current->kcsan_ctx;
> >         const bool was_enabled =3D READ_ONCE(kcsan_enabled);
> > -       cycles_t cycles;
> > +       u64 cycles;
> >
> >         /* We may have been called from an atomic region; reset context=
. */
> >         memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
> > --
> > 2.25.1
> >
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/20210729142811.1309391-1-hca%40linux.ibm.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210729155834.GX4397%40paulmck-ThinkPad-P17-Gen-1.
