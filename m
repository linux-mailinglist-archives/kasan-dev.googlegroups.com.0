Return-Path: <kasan-dev+bncBCC2HSMW4ECBBKGN3GXAMGQEDLEXDLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 24BD385E993
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 22:10:02 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1dc1db2fb48sf25903075ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 13:10:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708549800; cv=pass;
        d=google.com; s=arc-20160816;
        b=als3psf03nt/Ok/PHtFFtBFLP3flELG9fIV0lN9Ejyf5GncTedkoATnBrbs4Ty6vyz
         qDyyyBslwSCk7gg282kChFenuXkcM6fg4xY4c1RZRrt610fXytKa1Iq6UCkDCvrBoypm
         aqWIaj3fZJJU+JLgX6aP8i4MJarbjbJ0SmKQdOIR9nOmCZbtJbJBGecTPBTsUl5phOnH
         rm79HmcR3L9FqfSdO4ARMLq1zv+T9EcOPHtfuL50sfQRDmSecNPfyvEx+dMSC6eyHad6
         Fj8NjgMiC0fFU3tKCmtkZrzucQ9LJcvocvgdWGAwAsnu9wKt784/hGRxcHLsrxTXQRn/
         xU1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=IXAmspRu7B10bPie8ZvmOeEkzY55eiufHaS4odWR368=;
        fh=qBeSKVpkdPPXWDScwesNavhqp4yHP37Fb0Pmo57nnJo=;
        b=YNHyGAd+OrnkgXJpSQCWd1cE89WB2kVcMed7ZwYc9ht4UYlapBPASarPWk6i0XvFxF
         ody1N5LYWoqFwTdN4CZAW4Jjhj6xh5/V8lCDAOPhObSWzt1aIA5faClYmoNT++BVkd/J
         SCSRPLk8rI9eZXW9SCNoJNhF23GrDWC1CXChsS1UkK0F9VwEXpZR9tCCkkQPxfX+zo39
         EM6YZJ+Ka/DYbUs6QSEa3+XHpGEjXGD1XBCwkI6tfby5IT6bRb/EtcUmrjRdoJWzJv9u
         +BOJFeZAV9/LXDZLvKJh4Nyv2P+2PTooVj9vyQUg5Siy8p4TIPLTf5EB3SDcxVBAAbfq
         OQYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=eDkmcDpD;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708549800; x=1709154600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IXAmspRu7B10bPie8ZvmOeEkzY55eiufHaS4odWR368=;
        b=EM9E6h5lWtSRhLL4J5Rt9LS6OBD+Oj7XKTXfoa/c+h5H3rPNgPonY2v6jcGU2D8yRM
         PTfFrc/TaQmPDdT8pdRKYcjYSXrkdaQ5b7kF2QmFhxXdds3pnvr+1nHbE0Sd/x3qYARr
         3fcIuIxtqKqbfiX5COcOB0H5EdifVcRyOvGw698h4sot7kX9G3YKte2eKc+cZuejEyVi
         HnIaxKIxnOb7X/LsjESdJPTlrJl3xay4YGQNDRBTm3JZyYaGFUAqpzcxIH6MxQStGKu7
         hz2cBfbVLMAI54N71lpOLsTFatYnMeyYDZxw7WjlMdOIHjeopsECUOA/uoUTK+yzOSQ0
         I0yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708549800; x=1709154600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IXAmspRu7B10bPie8ZvmOeEkzY55eiufHaS4odWR368=;
        b=op5+S6jXL55xlp5RnfwEvmojENZfr5r6C1FLz/fCfcfz3P0CPEqDQJPmtxcm7vM313
         kJB3pc53udoGacN7319mgRc3mtEIUUyJWvFrWCzPojRZU7t4DmyvYhjQpb6/ieVi/yyQ
         /MVt65dfM6+zgV/iMg4XPSDIiiCv9OshBfrZguMh5n+4/wKZk82eY7bH4es08AvCr3nw
         ydWXP1ZxCWTPYaJy603utckGI6bDAxuZ7VstBsGX0Jc5/6/3RUQ4YNc+cya0zg60oBB5
         MgrupUJK8SNfllKUbCWT3oWrl2GnXcXEcajFzB4IiSgNKKUC/1ofzYyTlQ1gV6Xb6sT1
         CRnw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUH9M/kjBLKTApOEPNugKLncxgug/zF79Lr6MjEob6Mrlva6abTPWVNLvNQkijLSBDWYqIIohGMN2he7HDjLBx15BLzhqm36A==
X-Gm-Message-State: AOJu0YzvMKENdcZgOxzU6tMRvNvKe9TuO0pcFDMy/SOAbnzAg1yFEfvZ
	SiO+aDSq/2VGIBY/9TnIooDY9KrD4KYDYChdR3Nqpf9xxECiselg
X-Google-Smtp-Source: AGHT+IFxke8F2vPxFIc3sFpGVAan5sZm3v40af9gqZ3jQ4QNNeP7GhwEeCp7xghs4D3LXai4VH/euQ==
X-Received: by 2002:a17:902:ced2:b0:1db:cf63:b8d2 with SMTP id d18-20020a170902ced200b001dbcf63b8d2mr16713464plg.1.1708549800572;
        Wed, 21 Feb 2024 13:10:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:324e:b0:1db:5349:fc5d with SMTP id
 ji14-20020a170903324e00b001db5349fc5dls1310596plb.2.-pod-prod-08-us; Wed, 21
 Feb 2024 13:09:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX1JNXnv6cNsGKONN4orUCOxUNPPtM8WxR8KtUy1JZ3aDBXhXpX+4VOc/OkHF2rjwHDdoJsSxs4egRfe7Ec7ZD7Feq3qeif77fr9Q==
X-Received: by 2002:a05:6a21:3511:b0:19e:aa94:4efa with SMTP id zc17-20020a056a21351100b0019eaa944efamr24665517pzb.6.1708549799415;
        Wed, 21 Feb 2024 13:09:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708549799; cv=none;
        d=google.com; s=arc-20160816;
        b=ki+4D2hIe3L3/z8DRXCgaRyd3hmDN4j4mG2T+vzptzxsQob+V/kLQgADbYCalgmp+s
         l7tzzyG9Hc8oqPC/fqlG++OYZ0IhQHpUrDanOpVAoLf4fWD9bEtCETeG8jqPZrRrwqT7
         hEIYvD0Me3/iB1RuU2IfmF3hhN0LLaNQNEvFBDCqbSlFmCAJp8IQpL6GefiCoH0cJJkH
         IicTGgvyyyNr5eCdY/BRaEAt/mqHVXJSyU7u41g52XIaoHIaURG6wEKkh345vbWqsH3j
         PEFylu58vBBPK0IHN1Yi9Hl5QS9pXv7jRVemsbhAvQLnqKME7lbod0+PcgguchMk2dH6
         0Z+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6G+unPQpsnHPop/GA0eV3gHBK3dDdnNrDGYdK1/13VM=;
        fh=gFCPzXsmux6yF4zGinqNKu6wCh/jD9QZqb84dPfQeto=;
        b=awFbvE2hFORPtwv2ptXqnoLYwO5Q+Tu9rMpmu1fdeAGcu3U82P7FqnD4cW7mOfBmDE
         ytXhjH3aGio3gQnGmfGeIrhQ8hBB0NtMLnp6nChAVoRGHfc8aFNKYNVecIvkAodM7AzP
         zm8cGwUjZtEsnjstKsoS0ssetXhX0lW1MMeI6t5/HNnZj8a1BACYbQKE0y634tzn2OVS
         +th3Ed5vNhDoChhcwyD2h7m4FZSr2ChafoyklUaeicN0PP/OaA3rp9xyngy86Xe2z6PB
         6/6Ne7+tpKOhEWnZE589o/mPKAtpPmPGGaz+9+X0kZraanqsMfIM9p71C1vBIrFzP8AR
         2J8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=eDkmcDpD;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id a5-20020a17090ad80500b0029905bdb9edsi843199pjv.2.2024.02.21.13.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 13:09:59 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id d75a77b69052e-42dc86cc271so37876001cf.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 13:09:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVZonWd8vs93ilEABe6s8gM92eVrxAdHeRUH3viWLR8H/9gralAmYZKcHHpcUasbNyZmR8xzICAWwVHpH9yeyjdgfUPOfbmW2EM1w==
X-Received: by 2002:ac8:5f06:0:b0:42c:3b86:acb7 with SMTP id
 x6-20020ac85f06000000b0042c3b86acb7mr18725477qta.39.1708549798307; Wed, 21
 Feb 2024 13:09:58 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-2-surenb@google.com>
In-Reply-To: <20240221194052.927623-2-surenb@google.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Wed, 21 Feb 2024 16:09:21 -0500
Message-ID: <CA+CK2bC-uMw6hSNRCeWQjKDihd7=fd01g9VyQ_Y1iRwcq0LAaw@mail.gmail.com>
Subject: Re: [PATCH v4 01/36] fix missing vmalloc.h includes
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b=eDkmcDpD;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
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

On Wed, Feb 21, 2024 at 2:40=E2=80=AFPM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> From: Kent Overstreet <kent.overstreet@linux.dev>
>
> The next patch drops vmalloc.h from a system header in order to fix
> a circular dependency; this adds it to all the files that were pulling
> it in implicitly.
>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bC-uMw6hSNRCeWQjKDihd7%3Dfd01g9VyQ_Y1iRwcq0LAaw%40mail.gm=
ail.com.
