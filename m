Return-Path: <kasan-dev+bncBCKMR55PYIGBBKWOZWRAMGQE72QXDPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D56D36F66C0
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 10:04:59 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-3f33f8ffa05sf979525e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 May 2023 01:04:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683187499; cv=pass;
        d=google.com; s=arc-20160816;
        b=mDrZNukiE3mmqkdX+ZrlaJWZvDsxJaASK1N3P29fqW2vAZW3NiHACQzGZUNda4pSom
         AfBufKeqD3e9mK5C1gOEx4jzz1Nz1qsp1/vtWjHwxrCkoy1/xBHwOVXxJ/chzfftDl+b
         zk+rYxBl91BL6e6td8jPohNU/gkxeLtA8ZDEjQuPk1f5RMUUHqEAHbCcqRxgnYku8rsG
         PoG7p/sFBW2upai07cZqMhsmKzJCtFQpy3OKvKWgS+FQ+7hIG4kyWKjx+NCa9mm6pSuc
         I7DRBbIC+rs8ilCtYoBWMM6JynW+9nQ3M8BKQAUPntrfdxgZXV6s23R2OV3hPFjAbG+V
         rycw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=kwgBGHFFMiD5tZS0GS71/2SRAWv53yZ/P9aFBr+f1gk=;
        b=mRFpx+E7RBp/VTCVc1mmIEVywGsoXtl2v4BcqLstMtK9CoopA4lPIO1LZIXALrcW0U
         alBQAZBTICfp5At1GgQlnwLHnv36U94jzk3jleIptcM8DobY7sYxt7K5+3hvpefNTnqY
         CX7tklFk74Li2AZ7Gtj/QWkOwCAUPn0PIFE5UWbOeXtjf+OqzfsBBmO2jg4GGR3spCKF
         gQlzMTEeejDbrcr23+j1oarBLbQwAk8hzq4OHnQHVlQv1KUAG5q/kLZFI5XIx5wQniFy
         ljoATmlgZ8d7KZ/qWMw1G0QV6V/RJ/q+dj7lFlldB3iq/JOPArVRFGqXmnHm0BINACvn
         /16A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=WD6TCa4j;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683187499; x=1685779499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=kwgBGHFFMiD5tZS0GS71/2SRAWv53yZ/P9aFBr+f1gk=;
        b=R1Ngt0DDd8rgR6jO4DoWfVaR9DpXj1GLRoGWCg467P6iXynUDiAULgrgGe9G1grVUL
         41xqxAdiJskuYoWxa8XZIGDIfzTZ636t43zR8u6yHN6/enCtWlSCQ585pRSFWvuLpOzl
         N2BhQ/W7lOD/eJwR0Hp/t83p/lnL/oG/4pnwQlCXQ9gx1GOjhfamzd/tgknpyV5IDqSs
         mhO653m3OqgMm/fCpUD+xWVE4Z/oUGrh/2p2FsasZ9Y7UZvgGSVCo97DkEOW/4h3o8iZ
         +ZsFSpxH7dSYFeEi6EhOI5xAvi7zDaO5momDg/Ui93djnQ30p7cd7O/hGTgAo1t1IZSp
         XOyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683187499; x=1685779499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=kwgBGHFFMiD5tZS0GS71/2SRAWv53yZ/P9aFBr+f1gk=;
        b=gGnlA5BQeXArR3ZZvfnOZLKMa/dE6CXkzdLhFa6hi5qQczNeJTWkIroefFtZT3zvGf
         pdkgVLwcEtKp64eTP2Q9O4Q3EcpnlmtomEdeoGrR5VZQjxFet2V+HlrR7p1JPeVacMrx
         asEJQ+X8CafAxbNquqsbLmCw9ygWSFUMFzWSJ6aNiDLt9FlAfo6MWhQ+xSguddfcl8r8
         hBaFjUeDSfBbq9xmBr0LWjdrA6iVv/0r76yjjvAPAW/M8RuFXSk6YZc72hj2no8lYr8j
         MqRXWqIEEa60O+XJGVlCLa+xqXIy0xRnDalhoQmHb0Nv4qIY+6r50aeS4VnWeHdrCxMq
         +Khg==
X-Gm-Message-State: AC+VfDzYulamn8rQegrcMNMzkYLgBxzi0F3sQ3btJIz5KM58EiDqA0zs
	/WYn0kL5DwuOPvBMlKUCx2g=
X-Google-Smtp-Source: ACHHUZ6uLkAG9QuIQlg30zHh2LghKfHGzbaVdPwROAH9bxeJVl8bAapzglkWzEscj4M0rMymIFWx2g==
X-Received: by 2002:a7b:c389:0:b0:3df:97de:8bab with SMTP id s9-20020a7bc389000000b003df97de8babmr4154569wmj.4.1683187499177;
        Thu, 04 May 2023 01:04:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1787:b0:2f8:4432:9c7e with SMTP id
 e7-20020a056000178700b002f844329c7els418713wrg.3.-pod-prod-gmail; Thu, 04 May
 2023 01:04:57 -0700 (PDT)
X-Received: by 2002:a5d:6b09:0:b0:306:2eab:fb8c with SMTP id v9-20020a5d6b09000000b003062eabfb8cmr2108611wrw.42.1683187497683;
        Thu, 04 May 2023 01:04:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683187497; cv=none;
        d=google.com; s=arc-20160816;
        b=gCLniaps81QSpK/fEkIgBgzV+lzu+RynXHesJLw7D194dSaYElnT14IhnecoJiBvvz
         6GAnVKocXewWTS/eh0Fs03NvkjKtiEJlGTJH0d/mEp3nAlnlM/xrArq5i2vkHhF8LToC
         h2+E7jmGWeNX4nGiBo+gvcll5OskOYaaPIsePAWeWAz6PY/oxAcwaAU+ojH1pRi5JRkG
         bBf1jtPKO4SokyfkL+1xT/lxK5V6qXMT71LPjUWOzdvjITIswSwC+KC7ma36AmNtFwmt
         j0Qd351ggdfC72IQS7rB8gNVofiEmah4c1E8HYDlUGp/ZNdRjKfl4DSzYjepSnXgMILG
         qlOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=lYLdfOt08WRIoWLSWjtWBNIua1sIqT9o2eFAe/IM87Y=;
        b=WoNgLhFb8U+L5oKctwEHCfPtmjhaCQCPAhnBhXzW4VacSgmU9TuXCBn9AO4TknwKW6
         e1kh46Z1YI9qpV7bIq8LpkZLmUMk395md6ZuDYO79L5DSmYSRlaiuY3mIC/dLtd5asq9
         YmJSGtG4ZFTG2GevnG+pz7oXXURDB1vHInkUA9JxC0NNcxatpZaN5tpi5+o6jYpbwOT4
         qcUVKNC6rpDouO3kKwdsba1aFURye3F9wtnHEuOtm7r87G1w1Yz/wIBpqEZ2quhFDOWk
         Lefhhr2NblYXu71KP5PAzVro+ySpJq/L8nqAjsneu42OoRdyaiU6aY9eNsCI1GKLwcro
         Wmkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=WD6TCa4j;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id v8-20020a5d59c8000000b003063a286483si364813wry.0.2023.05.04.01.04.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 May 2023 01:04:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 564D920965;
	Thu,  4 May 2023 08:04:57 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 1B4A2133F7;
	Thu,  4 May 2023 08:04:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 17A6BilnU2RoKQAAMHmgww
	(envelope-from <mhocko@suse.com>); Thu, 04 May 2023 08:04:57 +0000
Date: Thu, 4 May 2023 10:04:56 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 34/40] lib: code tagging context capture support
Message-ID: <ZFNnKHR2nCSimjQf@dhcp22.suse.cz>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-35-surenb@google.com>
 <ZFIO3tXCbmTn53uv@dhcp22.suse.cz>
 <CAJuCfpHrZ4kWYFPvA3W9J+CmNMuOtGa_ZMXE9fOmKsPQeNt2tg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpHrZ4kWYFPvA3W9J+CmNMuOtGa_ZMXE9fOmKsPQeNt2tg@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=WD6TCa4j;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Wed 03-05-23 08:18:39, Suren Baghdasaryan wrote:
> On Wed, May 3, 2023 at 12:36=E2=80=AFAM Michal Hocko <mhocko@suse.com> wr=
ote:
> >
> > On Mon 01-05-23 09:54:44, Suren Baghdasaryan wrote:
> > [...]
> > > +static inline void add_ctx(struct codetag_ctx *ctx,
> > > +                        struct codetag_with_ctx *ctc)
> > > +{
> > > +     kref_init(&ctx->refcount);
> > > +     spin_lock(&ctc->ctx_lock);
> > > +     ctx->flags =3D CTC_FLAG_CTX_PTR;
> > > +     ctx->ctc =3D ctc;
> > > +     list_add_tail(&ctx->node, &ctc->ctx_head);
> > > +     spin_unlock(&ctc->ctx_lock);
> >
> > AFAIU every single tracked allocation will get its own codetag_ctx.
> > There is no aggregation per allocation site or anything else. This look=
s
> > like a scalability and a memory overhead red flag to me.
>=20
> True. The allocations here would not be limited. We could introduce a
> global limit to the amount of memory that we can use to store contexts
> and maybe reuse the oldest entry (in LRU fashion) when we hit that
> limit?

Wouldn't it make more sense to aggregate same allocations? Sure pids
get recycled but quite honestly I am not sure that information is all
that interesting. Precisely because of the recycle and short lived
processes reasons. I think there is quite a lot to think about the
detailed context tracking.
=20
> >
> > > +}
> > > +
> > > +static inline void rem_ctx(struct codetag_ctx *ctx,
> > > +                        void (*free_ctx)(struct kref *refcount))
> > > +{
> > > +     struct codetag_with_ctx *ctc =3D ctx->ctc;
> > > +
> > > +     spin_lock(&ctc->ctx_lock);
> >
> > This could deadlock when allocator is called from the IRQ context.
>=20
> I see. spin_lock_irqsave() then?

yes. I have checked that the lock is not held over the all list
traversal which is good but the changelog could be more explicit about
the iterators and lock hold times implications.

--=20
Michal Hocko
SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFNnKHR2nCSimjQf%40dhcp22.suse.cz.
