Return-Path: <kasan-dev+bncBDW2JDUY5AORB2G66WWAMGQE44HXK6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 38EE78289B5
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jan 2024 17:08:10 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-50eaba5febesf2264416e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 08:08:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704816489; cv=pass;
        d=google.com; s=arc-20160816;
        b=1C9lWJuCFdlbOfeFxQZKzno0eqTUaEDrl2FP2inmvACnzX5mzPgg0anR2YRKgGuA8j
         2FsIDPQALAuRc1uyJJcmjqrNnGVd2N5KagEBByCBhSL/oO5GavEIlzIZIcMpcivm+gm9
         iIxszuCM5Mf3JyfElGFgioXf0osWTeU6WlAFeC0amNNaZ/2lbfwY9s+oj40Q3R44JMq5
         94kTVNnrlT4jGTXvs7DOSOdOtZAvB2CkE+5kv8M9wUX7jMhGeaZlrBvjBDV9/mNnK2+i
         FX9iw6OymF0iwrrYE8SpJ/4FNrryuZNVp5Z4/h+X/eNmUTd5We59UIobRQ9+nF4UOw8A
         7wYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=F5xgv2P1WoqKfkjM3qVqsYzWA5cCiGtfP7BllhrxJCQ=;
        fh=DGU/dtnt2ulWZYlVQSx4hsKzh7sMKDoRN8xy+CaXv1I=;
        b=DzpMpztqAhB3c8WIBibd959maZoPgeAGbcdas5EsXPIuvhqHKCGc8B/YsYl+Sww6zd
         kyMErplDGnC1/SCQRuRQ3gyhb1OUxZCRgeNJLHZn4rl0AcYP0GgBxF6c0YgIAoKB/BNf
         slOQ7AkmHs5FchGd2KEpPOciUAqAe1+XORUS1s/HjT+Ly+oi1GIhDCSXk3CrXlDu0/4c
         Z5XoESBwcM8jzDXS/lf4au8TvmCPhVTlyPN43jDF6i1pO4Y5l1SXmfOFhBnHt7YXcf5+
         X5ugVyl49erCixv4sKVUD0nSOPQp0iLZt5DpQ8lTRgZ1/CJIFc/ueOEOXaqwHPnFBzOK
         7FEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="mN6/RGU5";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704816489; x=1705421289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F5xgv2P1WoqKfkjM3qVqsYzWA5cCiGtfP7BllhrxJCQ=;
        b=DsebXgQ2wJXz0vPjUV15X4yYrdF8ppaDFipZuLvALekLNcB4ejbnVEorN9axLOY2YZ
         RSz+VDJ+pBQxK7rs/NbbUH48f4OaOJZdJqPPZ/mUW05J7XrYh+U5wX7p2A2IZ5g19/4e
         v+dedG3H1PKKqZcgLx0oESJQ+9Holy9l8KTgFANMRd8vow46Jt7czg++Y3GSPJseXS7T
         iEA7fngPkgYJ0/WBk9sgQXL/OlFVuLYF59LROEH0F4SFhxNrKD7KAvFzT2ArpDuOdhYl
         Ibvm2Fs+t5250BgpV7eIwEKuKj6qBY1BDtNwaLnNz7AHI68yupWfSu7QHaRB5CBT53Ym
         IrNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1704816489; x=1705421289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=F5xgv2P1WoqKfkjM3qVqsYzWA5cCiGtfP7BllhrxJCQ=;
        b=Aw/ImItWf6tHRKl9E6xFMW/CuFWXzYRk9cPu5Vs6ojz1uE7AWwpSqGsFdcctnAtbz3
         3QJQoQJcjTmXKAQOGLZYWwoi9fpEahZvcqGSwBcvN/BeQY8MDJ2WfDVIcy2Lllenysj+
         voEgf/xz+9k4e3xmtBHKQBpXWKdmQuXKL3EolGe7abqXzaq8G1ZoZOw3j3D9YpY+3UTV
         qu1RZlDFpYG6jS0JZ6DB7S9kMvRjV5syoHk8GRrR6Nm0CKuZ/q7Ei4vHutMOiK9uqk0J
         Oo09M4WS2EVZVlgspxBDIwhM3duuiNTThSx751pb3MDpDEG9f6PZuig1Rb505Q4nrZeR
         b6Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704816489; x=1705421289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F5xgv2P1WoqKfkjM3qVqsYzWA5cCiGtfP7BllhrxJCQ=;
        b=gxJLouWP0rUY6xXzKpn27+unSDSOBUTV44YXgcAy+MJlAqzIwJpGcoV8K43i//7hYm
         n096lPjEIkxBlhkGCEEea578APHI/Oa+rnLlcup/ngU810vOjFKB7xS18TVtmx04h0Cu
         EMlmTrqxqH5WJRxtc+uBfy6WRQmojbZM8eIOIw2+mxTjJpFYFmMVUFQqdCyAblmk4b8H
         ilqG3H4X0NSG3mHDJ9lnXkEa4rVRHGDD84BpHd77IBKl+2HF0zMXA0r0HXc1bnqeyOQE
         lZgJeKzONzgj3QIwaDbsirJrO0JhWc14pIebqmtlt/IDVkZuVeb8DVd2I408rb5AWZf3
         hFmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx6oBmt+tB0wjWQ9/OueDsoHeuUFJO/BV9U9bS5S60Tj6ZPq0DG
	yYkEaMCbgr1oONPnFc/fI4k=
X-Google-Smtp-Source: AGHT+IEpRS4b/IwjE0O2353V1uQkvCZ8aFFuvYYcbk03veMPZPPPZXFMHNerMmgkGm2rHHzjUf3QZg==
X-Received: by 2002:a05:6512:110c:b0:50e:8119:fb60 with SMTP id l12-20020a056512110c00b0050e8119fb60mr2375286lfg.13.1704816488908;
        Tue, 09 Jan 2024 08:08:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:a8f:b0:50e:7eb7:bab8 with SMTP id
 m15-20020a0565120a8f00b0050e7eb7bab8ls171266lfu.1.-pod-prod-01-eu; Tue, 09
 Jan 2024 08:08:07 -0800 (PST)
X-Received: by 2002:a19:550e:0:b0:50e:aabc:34bd with SMTP id n14-20020a19550e000000b0050eaabc34bdmr1902066lfe.124.1704816486667;
        Tue, 09 Jan 2024 08:08:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704816486; cv=none;
        d=google.com; s=arc-20160816;
        b=a3/PXhy88pl3nfnl39wtY9pn9ohWJ+t2hd6MFUMMlmUaK13yhu+e1QPPVbCuNDDnaM
         s6HNtTDWWd+vdJF/0ZMTFJTUkmRawknCBs0sP2zyHjwbXF5YkksnJq2yzrMqsPXYXZu8
         AsdIfNHsWUAHDSzhcixx4FLNiZxUdCaNDGRFxUtgWeudghmjlT9cgdoyZKq6tpUHgObm
         hwXGUc26VBR2eEn7cs0INJt6kZQzNdeWZReHaDdexRfnYs/Fy87QUdJkbkremJPl9WWM
         iJjcAJ/7ApR/JifCfZocHBo/B4Ci9NpMjopKkV43SG9J9qE1MU7PA0WQGdwHF30eg1Vk
         mipQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jjxiE4RN/pGMzfyi7o7airmhzjWZK0FgpxYzjcRDcB0=;
        fh=DGU/dtnt2ulWZYlVQSx4hsKzh7sMKDoRN8xy+CaXv1I=;
        b=i7hfK4+hwtln/YPalZ1ZDmLP8h3VwNqjYDRvEMfVCLLPAwcBAX7ui1Fav0b3o7nBxI
         xKGog4OP+E97aEh57PV7wLQoN3LmijksOzGvMf7S4Skzne7x6w8zlZs7lUkNf1QKvlxr
         Ncz4JLfB3V1uOY0VuLsWNGW9jKHfZNb/5gD5jHCZsGThcE1whFR8YhXvfM0N+Ac7vaxy
         pENn/eD/pChk/TAUHGzrQ8DnnzvXTNQ0qNtRK2Zn2yWY9EAkVrFklj0ROymFnm0Qd+h8
         Rc/hdER4xLJ3Y1jS8XBBd42NCreUIGPtRnTuPOznqIk+C4itofECT3kGpS0hIJWbZBRO
         dC6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="mN6/RGU5";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id z16-20020a196510000000b0050ec7483a0bsi115504lfb.3.2024.01.09.08.08.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jan 2024 08:08:06 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-3376ead25e1so1629814f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Jan 2024 08:08:06 -0800 (PST)
X-Received: by 2002:adf:ea82:0:b0:332:eaa7:56b0 with SMTP id
 s2-20020adfea82000000b00332eaa756b0mr661226wrm.14.1704816485763; Tue, 09 Jan
 2024 08:08:05 -0800 (PST)
MIME-Version: 1.0
References: <5cc0f83c-e1d6-45c5-be89-9b86746fe731@paulmck-laptop> <20240109155127.54gsm6r67brdev4l@revolver>
In-Reply-To: <20240109155127.54gsm6r67brdev4l@revolver>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 9 Jan 2024 17:07:54 +0100
Message-ID: <CA+fCnZewUEv2BMX-D=a+5wosusM-H3tOBpeJe6oyu51mMLXQnA@mail.gmail.com>
Subject: Re: [BUG] KASAN "INFO: trying to register non-static key"
To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: sfr@canb.auug.org.au, linux-next@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: multipart/mixed; boundary="0000000000000aab15060e8585db"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="mN6/RGU5";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
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

--0000000000000aab15060e8585db
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Tue, Jan 9, 2024 at 4:51=E2=80=AFPM Liam R. Howlett <Liam.Howlett@oracle=
.com> wrote:
>
> * Paul E. McKenney <paulmck@kernel.org> [240109 09:04]:
> > Hello!
> >
> > I get the splat shown below when running rcutorture on next-20240108
> > (and some less-recent -next versions) on scenarios that run KASAN and
> > that also enable CONFIG_DEBUG_LOCK_ALLOC=3Dy.  I am running gcc 8.5.0.
> >
> > Bisection fingers this commit:
> >
> > a414d4286f34 ("kasan: handle concurrent kasan_record_aux_stack calls")
> >
> > This commit does not appear to be trying to change the annotation
> > required of KASAN users, so I suspect that the commit is at fault.  I a=
m
> > including Liam in case Maple Tree is the bad guy, and should call_rcu()
> > need adjustment, here I am.  ;-)
> >
> > Thoughts?
>
>
> I think this is ma_free_rcu() registering mt_free_rcu() in
> lib/maple_tree.c.
>
> The commit you point to saves and restores the irq state in
> __kasan_record_aux_stack(), but the trace below shows it is called prior
> to irqs being initialized.  This isn't what lockdep is yelling about, so
> what am I missing?  Maybe it will be caught after this issue is
> resolved?

Hm, I see a discrepancy in the KASAN code related to the guilty
commit. I believed it to be harmless, but perhaps it is not.

Paul, could you check if the attached patch fixes the issue for you?
This is rather a quick fix than a proper one, but let's see if this
one works.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZewUEv2BMX-D%3Da%2B5wosusM-H3tOBpeJe6oyu51mMLXQnA%40mail.=
gmail.com.

--0000000000000aab15060e8585db
Content-Type: text/x-patch; charset="US-ASCII"; name="kasan_record_aux_stack-fix.patch"
Content-Disposition: attachment; filename="kasan_record_aux_stack-fix.patch"
Content-Transfer-Encoding: base64
Content-ID: <f_lr6jioa60>
X-Attachment-Id: f_lr6jioa60

ZGlmZiAtLWdpdCBhL21tL2thc2FuL2NvbW1vbi5jIGIvbW0va2FzYW4vY29tbW9uLmMKaW5kZXgg
MjIzYWY1M2Q0MzM4Li4wMTQzYzFiODIwMDQgMTAwNjQ0Ci0tLSBhL21tL2thc2FuL2NvbW1vbi5j
CisrKyBiL21tL2thc2FuL2NvbW1vbi5jCkBAIC0yMDgsMTAgKzIwOCw2IEBAIHN0YXRpYyBpbmxp
bmUgdTggYXNzaWduX3RhZyhzdHJ1Y3Qga21lbV9jYWNoZSAqY2FjaGUsCiB2b2lkICogX19tdXN0
X2NoZWNrIF9fa2FzYW5faW5pdF9zbGFiX29iaihzdHJ1Y3Qga21lbV9jYWNoZSAqY2FjaGUsCiAJ
CQkJCQljb25zdCB2b2lkICpvYmplY3QpCiB7Ci0JLyogSW5pdGlhbGl6ZSBwZXItb2JqZWN0IG1l
dGFkYXRhIGlmIGl0IGlzIHByZXNlbnQuICovCi0JaWYgKGthc2FuX3JlcXVpcmVzX21ldGEoKSkK
LQkJa2FzYW5faW5pdF9vYmplY3RfbWV0YShjYWNoZSwgb2JqZWN0KTsKLQogCS8qIFRhZyBpcyBp
Z25vcmVkIGluIHNldF90YWcoKSB3aXRob3V0IENPTkZJR19LQVNBTl9TVy9IV19UQUdTICovCiAJ
b2JqZWN0ID0gc2V0X3RhZyhvYmplY3QsIGFzc2lnbl90YWcoY2FjaGUsIG9iamVjdCwgdHJ1ZSkp
OwogCkBAIC0zMzgsNiArMzM0LDEwIEBAIHZvaWQgKiBfX211c3RfY2hlY2sgX19rYXNhbl9zbGFi
X2FsbG9jKHN0cnVjdCBrbWVtX2NhY2hlICpjYWNoZSwKIAlpZiAoaXNfa2ZlbmNlX2FkZHJlc3Mo
b2JqZWN0KSkKIAkJcmV0dXJuICh2b2lkICopb2JqZWN0OwogCisJLyogSW5pdGlhbGl6ZSBwZXIt
b2JqZWN0IG1ldGFkYXRhIGlmIGl0IGlzIHByZXNlbnQuICovCisJaWYgKGthc2FuX3JlcXVpcmVz
X21ldGEoKSkKKwkJa2FzYW5faW5pdF9vYmplY3RfbWV0YShjYWNoZSwgb2JqZWN0KTsKKwogCS8q
CiAJICogR2VuZXJhdGUgYW5kIGFzc2lnbiByYW5kb20gdGFnIGZvciB0YWctYmFzZWQgbW9kZXMu
CiAJICogVGFnIGlzIGlnbm9yZWQgaW4gc2V0X3RhZygpIGZvciB0aGUgZ2VuZXJpYyBtb2RlLgo=
--0000000000000aab15060e8585db--
