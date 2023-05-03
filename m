Return-Path: <kasan-dev+bncBCT4VV5O2QKBBHW2ZCRAMGQEP64MRTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AFE66F5518
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 11:45:03 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-74e3f0a8349sf272350985a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 02:45:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683107102; cv=pass;
        d=google.com; s=arc-20160816;
        b=fsSPP17nd2kMuQIEUxSjCpY59JivuK8SuzbaRk9kbGYcJYxIVzWHs5fybwSqV/ojj1
         a0WJCxYuradscCa5qIuVD7tGM6BC0W0gAgU63c2ahhuslExPwwHT9K/nyuKeAd7+ZSPJ
         TwVbPw/BScsP1REz9F8uNhTspc9eyvc7HovU3v52lvbDSZUBy5caQteqlNodnom3ZPUy
         rZr43ohZq2v8wpxe7BvpaeVKuk5KFJEYbOTs7t9b7V/pEqdVenCDu9I/SDi6eevxQwbr
         z9Qp2H7m+0sgubilFcCLRNeI+vX9z/67l7xevU5+JIRGHdOhjHChgqUNG30fMHeIU00f
         ilfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=QzuYC+WluCS1+KMV446Dn5YnGJN+a1HfZWpv5oy4Abk=;
        b=e7q/xOtYCr4rhik3rqSA/vIkwX81cCjzXA83i78oYdWcdStP45bC/ZHxuRI+UwQ3e+
         zRK8cPt1DbSmJXgyyrUoEOCrN96PIUoAv104Mw+6H+RMesLmu6nOcLubNwX9GEu9f54R
         yGt0KqLn56vJY38XC+ZygkkzoxYpQAJWyWTGWhB8+r3G3rD1GTzeOKNsdjrJSdhEpWa7
         Te6hI89mNyTU5qSfP9jCsqhlA3o5YrkuYXNTTgRCBOrQWhq5FDuwRvJn5nwQqOYqoxD6
         6s3ro+7JbUx13C3kZAsSj/zjqHcqEPVC00utkJ7kRVma6lu7ACqe5jlaeE+P7Mhn1MtK
         jO4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=VhDxBqzj;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683107102; x=1685699102;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QzuYC+WluCS1+KMV446Dn5YnGJN+a1HfZWpv5oy4Abk=;
        b=hqCAQXN7V4J2AIYjdsbdUgjLmyC8QBn/31PUSbuyIHJU4OdVPmIlR1jslkKA4ePZ54
         EKLGUbFJZyC6aMkb6o8bthuVAYHvkrfXZ/cIA9Q/y65TMgKZWzhiYEbnP+Qd1CZWr2PR
         UfnjCdtdshLi6/dUFARASaqREQujvMMAHuvp4QtGLhd1jk8hkcGOG/3ZFVE+b5yhO/jZ
         3rEcOX1vhzLbY6K39U7MvdFfEsKtQkNgb4i7Qc4ELKqjtTpoAr6QkLIefBaguuow2q6T
         lE311CMxIjOw6AWdn3wSQir7/mTr5ozQZqIq1sRyhGjLJS5ePX6khI+UzXNa9XAZ+tiS
         qoQw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683107102; x=1685699102;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QzuYC+WluCS1+KMV446Dn5YnGJN+a1HfZWpv5oy4Abk=;
        b=PsTARthm6MyEukDvAUO/bUswKJU7v1nfLRYOuV+OlWVq/zfH884TM1AULe7obWkCWM
         IgW4EsgziChA7gfTZxspU7K0J4rMqg8uwEklmeXWgMIyo2MWLjZjfEEcibVDEVvFQvC7
         RFsB2y+6Vg6GiJ6n8LUHFCSI1WfweKcx/v0K2tcZVOfKs9n/Xry0fOKNlP7nWbWcRl2O
         0JZlrAI2/2ijH1FABU2KjhgNVHpL9EqY2dI2R3Ko3YADcwwGiTwuG3jRYEdrQhr7wZKc
         31ODGtXcGm/4AA9SFS2tcO9jArVu4+DMcgoOmjkqGYiEh4YlftyHZR00ROLW9lUPZLgL
         7VHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683107102; x=1685699102;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QzuYC+WluCS1+KMV446Dn5YnGJN+a1HfZWpv5oy4Abk=;
        b=da/M0BNCUSIrYX3CKTnJbB8IRkJ1m/QGa23PtLfTwpOm9hTopZFhND1paM82PWIWZB
         uaMuvek2HG0JGuProA/x17UBuzMby6ChnklK5AEl2yaoVWCeJB4lQXfbMTS+HYtXa4ny
         JOYNaaxYwPTnyCrXiEq/k/XXaQXo1O84lnxpQdzBQ2iiuq+xw+s0vTgr0Nqc6Bd+jZLC
         tCQgO1jOMiK/79t5LNFiKDiVS591rQK7e1++95XnmntrRpmcWMjLO7UsjcOiDkCdxImw
         NpnKttD1nCaj4ZyrsEp5qeUpk3LenndnZT/Ab/dOrgsI8WAeEJXa9GJRkQ507+UP6+qY
         kNKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzxjLq6e/RjZf3CWA2tJpGfMB9d0pMyNsjEBocLoISGB2DkY2h2
	4oAsnWTXU2jMny66CclPM7s=
X-Google-Smtp-Source: ACHHUZ7s8VeK9Ml4A7ecTTc17N9c98nq5onES1UxBzn8lCZ4ZaFUR68j3YVItfbdEZj4MrCCE8cwZA==
X-Received: by 2002:a05:620a:11bb:b0:74e:8b1:37f6 with SMTP id c27-20020a05620a11bb00b0074e08b137f6mr2240424qkk.10.1683107102137;
        Wed, 03 May 2023 02:45:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:250e:b0:3ef:5998:f92e with SMTP id
 cm14-20020a05622a250e00b003ef5998f92els14739575qtb.6.-pod-prod-gmail; Wed, 03
 May 2023 02:45:01 -0700 (PDT)
X-Received: by 2002:a05:622a:1009:b0:3f2:655a:a6d with SMTP id d9-20020a05622a100900b003f2655a0a6dmr3314955qte.4.1683107101600;
        Wed, 03 May 2023 02:45:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683107101; cv=none;
        d=google.com; s=arc-20160816;
        b=h2Lho3FqTwq1OHWiwEitewLTGG1ykITDNRIEjyGrJfHK1U2Gnu0m8lxoqJnU+qB5ik
         +R+cqR7X4x+J12EDxrKA5TyTAPUxTHa4OcmmUTd8wxeyhujTeDwVtue0S4bnhG5nqA/4
         4ff76IqQ1p9mWGSnh7HPw4QvJmcS/LiSFyTUxK/bZNyggk/fpMyZ1jhe39cb2Ljv3mKA
         viiJXZiAkkkjvU/9WcKpZpJWYKGRhqAmv37i3MPtnwbcPwQe371ehgNJXI+1lPicogXS
         1RoVNG+740gA8BTPo7ZElCcmYdOomYXzbiFtCskXUx/JPJj20FFhm+RbTb7159tD5Wbr
         +FsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vu1/caV96gPScaPWMCtnkWIUIUcxiUGOiQt9hLifgPw=;
        b=VyPMX4CPUjTEBZ9CtaeuOWTZEYPCJE1spQemWSddmnswgkGjKIidaaU3buewJBzEz7
         QDAo+nndYPgNVhBOss594DXj9DitYvJpZfqJBZ7kVl7iG7f/sP38O4cQCLrn0y6cIJSj
         QDo9AKxS4nEH/YpmFLblkMCT90LOpYYrgKw8qeb5Js2dkYE4g0PAPeogMIs84F+OL5ko
         5VfCFR/w8aTh/L953/CeID2Mukp96XMzQMBB8phqEEJFQRCg43N7KkaqP9XdxP+8w/Is
         KRsrHPtdBpthIbF+KdERscCjuyVO6c2MQpBp4oMonl47v8hWWA1zhm08jvEasPvDaZse
         RhMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=VhDxBqzj;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id z3-20020a05622a124300b003f0a7afd790si1526183qtx.0.2023.05.03.02.45.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 02:45:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-61aecee26feso15004716d6.2
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 02:45:01 -0700 (PDT)
X-Received: by 2002:a05:6214:2629:b0:61b:17bd:c603 with SMTP id
 gv9-20020a056214262900b0061b17bdc603mr10563566qvb.9.1683107101117; Wed, 03
 May 2023 02:45:01 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan> <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan> <2f5ebe8a9ce8471906a85ef092c1e50cfd7ddecd.camel@HansenPartnership.com>
 <20230502225016.GJ2155823@dread.disaster.area> <b6857aad-4cfc-4961-df54-6e658fca7f75@suse.cz>
In-Reply-To: <b6857aad-4cfc-4961-df54-6e658fca7f75@suse.cz>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Wed, 3 May 2023 12:44:24 +0300
Message-ID: <CAHp75VddBGrrkRGQcU=ZOXANaj2SznPGG4eQ8Q2NrGYbLK7Xog@mail.gmail.com>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in string_get_size's output
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Dave Chinner <david@fromorbit.com>, 
	James Bottomley <James.Bottomley@hansenpartnership.com>, 
	Kent Overstreet <kent.overstreet@linux.dev>, Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	=?UTF-8?B?Tm9yYWxmIFRyw6/Cv8K9bm5lcw==?= <noralf@tronnes.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=VhDxBqzj;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 3, 2023 at 12:28=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 5/3/23 00:50, Dave Chinner wrote:
> > On Tue, May 02, 2023 at 07:42:59AM -0400, James Bottomley wrote:
> >> On Mon, 2023-05-01 at 23:17 -0400, Kent Overstreet wrote:
> >> > On Mon, May 01, 2023 at 10:22:18PM -0400, James Bottomley wrote:
> >> > > It is not used just for debug.  It's used all over the kernel for
> >> > > printing out device sizes.  The output mostly goes to the kernel
> >> > > print buffer, so it's anyone's guess as to what, if any, tools are
> >> > > parsing it, but the concern about breaking log parsers seems to be
> >> > > a valid one.
> >> >
> >> > Ok, there is sd_print_capacity() - but who in their right mind would
> >> > be trying to scrape device sizes, in human readable units,
> >>
> >> If you bother to google "kernel log parser", you'll discover it's quit=
e
> >> an active area which supports a load of company business models.
> >
> > That doesn't mean log messages are unchangable ABI. Indeed, we had
> > the whole "printk_index_emit()" addition recently to create
> > an external index of printk message formats for such applications to
> > use. [*]
> >
> >> >  from log messages when it's available in sysfs/procfs (actually, is
> >> > it in sysfs? if not, that's an oversight) in more reasonable units?
> >>
> >> It's not in sysfs, no.  As aren't a lot of things, which is why log
> >> parsing for system monitoring is big business.
> >
> > And that big business is why printk_index_emit() exists to allow
> > them to easily determine how log messages change format and come and
> > go across different kernel versions.
> >
> >> > Correct me if I'm wrong, but I've yet to hear about kernel log
> >> > messages being consider a stable interface, and this seems a bit out
> >> > there.
> >>
> >> It might not be listed as stable, but when it's known there's a large
> >> ecosystem out there consuming it we shouldn't break it just because yo=
u
> >> feel like it.
> >
> > But we've solved this problem already, yes?
> >
> > If the userspace applications are not using the kernel printk format
> > index to detect such changes between kernel version, then they
> > should be. This makes trivial issues like whether we have a space or
> > not between units is completely irrelevant because the entry in the
> > printk format index for the log output we emit will match whatever
> > is output by the kernel....
>
> If I understand that correctly from the commit changelog, this would have
> indeed helped, but if the change was reflected in format string. But with
> string_get_size() it's always an %s and the change of the helper's or a
> switch to another variant of the helper that would omit the space, wouldn=
't
> be reflected in the format string at all? I guess that would be an argume=
nt
> for Andy's suggestion for adding a new %pt / %pT which would then be

(Note, there is no respective %p extension for string_get_size() yet.
%pt is for time and was used as an example when its evolution included
a change like this)

> reflected in the format string. And also more concise to use than using t=
he
> helper, fwiw.



--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHp75VddBGrrkRGQcU%3DZOXANaj2SznPGG4eQ8Q2NrGYbLK7Xog%40mail.gmai=
l.com.
