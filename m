Return-Path: <kasan-dev+bncBC7OD3FKWUERBA5DX2XAMGQE5BML3GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id E61EB8582EA
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 17:47:00 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-42c739603b0sf357651cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 08:47:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708102019; cv=pass;
        d=google.com; s=arc-20160816;
        b=TvdJoRTn68l/77nCjExfvGX0Sd840TIyTSDJV6/2DUPL5iaR4+VJt7lr0aRQbGdNM7
         vrsreNUg8Q0rVmw/pLFqUsMyaALDFU7TqejvJfjoK68pGLA1XQS+NCbFXqp0z8xi5uTR
         wozh+bmz1GxKs9x03vsWhiJUWyl+g3/VOhtH46mOFOKGQCRH8Ug4XXrJmhAE7Jj16aNg
         RRFL+NxODLREezgucv6Y/Sr2oA/ZS1D9s2rJqhEEfGr8ZNu0+qSbtfr3mi0E5tAJjIVw
         j3OHRr4KNbDvKffofhWhseztnzPBemHynMD6aZQ64h1RcITbw4gbH3G3eGXmEG+mm/dS
         p79A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MVmRN8WaR5fGYF6N3zimmFGncYOjQZgq4vhWLyGPaXo=;
        fh=ObIDyOtL/V4V8LGwM32CUP3+6xmBo/xAVrbB/Xhalzs=;
        b=ZZuY0pE1Xntvt2i72uZiV0CPsaWgD5kKChpcLPyd9+q8cU8O+iD3tON3k9VTGtC2CH
         +pn0RKKw5qn5m7QYlZ9LFF9ysS9mz6b8HrjX6aTICeWRx1Sup2Bo4tEWsHgrN0BC9QEl
         pM8zyvupsU7TeAI6SBIw76ayf3rXRXZTS1Fe/ZclMeLP6m8WxDQP3w1+BMDllK29cqRR
         dtqZrnP85C72dXZjza4GedIzpI9DpuSbCbAbUR7lz4LB+rMDIfjgn8g/XEjPsLiIh/m6
         9gKXMs+CMVGPy9Ijc48OsZNS72zVm6XZbFLU2ZUdL7Vj9ljqA1OeFFYpX5SuJ56BpY6m
         TOoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=b1m3xUdu;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708102019; x=1708706819; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MVmRN8WaR5fGYF6N3zimmFGncYOjQZgq4vhWLyGPaXo=;
        b=HVKoOM/OOkpOyz1+32QkaZHVcuqOYOp/012/nzfCciMEbtvqBerK+QB+kItX+DmHKw
         E2H64eotZJSdPP5Oaw53OIlD0d96k8O/F5dBDgGiVeuSTG5R5XHrQFxLY59n2OfwLCwh
         MLrRt+z1lY+0VZQMrdS9SL77IM4my/4moRCqKkqGajzhPOhVc+1yVP/rXHi/zzFeDwmR
         /GuqFIscAH2BcWrnjQGprM8vR97xSlKSvs+Shf8JCrKpQ699cOilW0NzHJBSkN5h2sYF
         sjn/5xfrA+1DwtsprEk9xMf99sH6J7jxQ+fgC8LaQk/9YU1YnIkfaPkHiW/D44aZpz4A
         Q9mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708102019; x=1708706819;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MVmRN8WaR5fGYF6N3zimmFGncYOjQZgq4vhWLyGPaXo=;
        b=KZt7DTuOK6migjkhGOGa++0AlbwqyUvj3hL/HXutl9xEFK6I5prCbXVwSnRUKev3wW
         L8QCD96dtRTPQoyi701WtuvT+ekncCc6gzh7iKo7t8pdjI2Hj4SRB0cu8Y3pK7b9/Ulw
         PO4pECWkRmkMOQFCbKI19qTf5ZlJqL8LWD3N5exR+b9DPOi4G53sD7CZNE59pyHtKdAV
         rI3pJWW8SHM1zfdJ2+qrtylt+yfR+wmgpIYpCborpyxaUKiOUIE3Fi2ADOhuH1XEY44h
         LEz/ruaF/7ybfWFHZaXbWJWxbtbsPfiJ3D/BsM6AdlF00XjhsuErrZGRDnJc44IC/NzO
         bbxw==
X-Forwarded-Encrypted: i=2; AJvYcCV3Gs0hcmrq9s1Uula61sahO0CgMZWRZptY3fqHfqXA3+7bj7CTzHn7tyo54/Of5j/74OlxdGZEJ4PDMaJ5QP22r4WjDlTV9w==
X-Gm-Message-State: AOJu0YxqwLWuywaCZK1wnURYTCYjN0kgrdGmk/IqlESySgmGZhXb/KvF
	Bgerdsx5T0S5R+1ZnuyzsKbGuhAJacncY0NiCa/2e0Q1pSHnK8Sx
X-Google-Smtp-Source: AGHT+IEbDLE/y58f9bKyomw3cyAcJ6Avm0y0/MA6w7aiZdljP6MR4y4jz1WBamTQu3j+CEKg4hmLrQ==
X-Received: by 2002:ac8:598a:0:b0:42c:757b:9409 with SMTP id e10-20020ac8598a000000b0042c757b9409mr389847qte.16.1708102019577;
        Fri, 16 Feb 2024 08:46:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c44:0:b0:68f:1312:8dd0 with SMTP id a4-20020ad45c44000000b0068f13128dd0ls1806255qva.2.-pod-prod-03-us;
 Fri, 16 Feb 2024 08:46:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWOT16AEdLnnl7R4fk9mdEhEX01LOgobjJoVbV+jqcICAJOYTtQSarpLQcvViDFsIe6flHNlUjqQVN/qBZ/xLMbpvw+8dDaCjacKg==
X-Received: by 2002:a0c:de09:0:b0:68f:2ebf:851d with SMTP id t9-20020a0cde09000000b0068f2ebf851dmr3198205qvk.1.1708102018756;
        Fri, 16 Feb 2024 08:46:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708102018; cv=none;
        d=google.com; s=arc-20160816;
        b=pxPMqLqcQzjjsY7romOQMnSZ69ndpKd2Wz23iCuBhjtD9FT8nqVZ488gbefDsw7t7g
         SMboIUAf4oWaIP4th9RYrbnrXBv718txYs4cuYWl28AFqNeQaTifYzTnfWXeAi7N63rA
         QJfhgalfY0/glhZbpZfpbjs9qVsxIXSj95gMto0EnwVXVmD+bVoEHL4/0sZoD67ojvq1
         9IfxA+uQDZ/STprInTflpUqL/0YRQdhv1//eA7QLZQaVaEBNzpjv01ScPfxjUnu/hoUh
         Wyjr5MDdwXLQE+LY13vnavM0VEBEv2Aw1w0HyAkDYr25MDla2xmU7+kZ4KbhpwJISwqz
         GP5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/5/86K2Z1hDqoZIqP7XxaxYaiR6tJyE2BrZYnn5TkeE=;
        fh=DxFczcIqYAnByq3kfivVq5XAXs0h60cie+Uge4GNeVU=;
        b=EOIadeFjitKz8TKFiPB82Gz1KeHmg1cyHbbykOUly5MQYuw+ThaoVRCUH4IfSQmC9L
         xyu/PCSFlmmHd9JHH5WNuyRygN3IqwxRT89EelPPkZof5060IOytiOX7x1tjKDmSdTVw
         bx46hj8zdSzsHzis/Xf4/izQRcWBcOSbsxEVKXx+VUYhPPHBNCphGLYnxV7MjB7pNhx9
         mMpNPX0ZjCxIslkDb8N/vhcK9hGxlkTU+QPiYzmGASFYaGAHxvH4KaKNUtny3A1O8dDI
         Pb4Go0qmR6tMFOVwz5uygM4P0mi69XCuDWETrZGqEYcIxfbOcxhMHSRLRaSfSXEal5SF
         CeUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=b1m3xUdu;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id v5-20020a0ccd85000000b0068f3225fa0dsi7913qvm.5.2024.02.16.08.46.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 08:46:58 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-dcbcea9c261so1174449276.3
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 08:46:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVVZHbKCINS5wyVnvHabPSvL9tVEfkGwmLh8Y4mHoFChZF4UqImSlhszixpG4ik/lTrCRgjWbYKuffnguEGdUR/D2iVUnu+48uAeQ==
X-Received: by 2002:a25:ae44:0:b0:dcc:6894:4ad4 with SMTP id
 g4-20020a25ae44000000b00dcc68944ad4mr5406936ybe.56.1708102018033; Fri, 16 Feb
 2024 08:46:58 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-19-surenb@google.com>
 <2e26bdf7-a793-4386-bcc1-5b1c7a0405b3@suse.cz>
In-Reply-To: <2e26bdf7-a793-4386-bcc1-5b1c7a0405b3@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Feb 2024 08:46:47 -0800
Message-ID: <CAJuCfpGUH9DNEzfDrt5O0z8T2oAfsJ7-RTTN2CGUqwA+m3g6_w@mail.gmail.com>
Subject: Re: [PATCH v3 18/35] mm: create new codetag references during page splitting
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=b1m3xUdu;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Fri, Feb 16, 2024 at 6:33=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/12/24 22:39, Suren Baghdasaryan wrote:
> > When a high-order page is split into smaller ones, each newly split
> > page should get its codetag. The original codetag is reused for these
> > pages but it's recorded as 0-byte allocation because original codetag
> > already accounts for the original high-order allocated page.
>
> Wouldn't it be possible to adjust the original's accounted size and
> redistribute to the split pages for more accuracy?

I can't recall why I didn't do it that way but I'll try to change and
see if something non-obvious comes up. Thanks!

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGUH9DNEzfDrt5O0z8T2oAfsJ7-RTTN2CGUqwA%2Bm3g6_w%40mail.gmai=
l.com.
