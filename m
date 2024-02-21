Return-Path: <kasan-dev+bncBC7OD3FKWUERBS4A3GXAMGQEDGENADA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 391FE85E5D7
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 19:26:21 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-5ce67a3f275sf782022a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 10:26:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708539979; cv=pass;
        d=google.com; s=arc-20160816;
        b=iKdniAAuYz5P58wQe3yvNnnCDPAGchKiuhmNIEUdqIEFhhsgHX3E+kmewlznV7juIr
         0AZmvvH9ut/zVJnn/NqzYXtUYuFHjOMT9lQYw7UrQK7K16Ms1fmJsss8vQkXdX2Qmk20
         WqqqW52Pb2Kr1nfhuxPvWIC8s76CBhIZp5GHRC4w89Igge6Pr8X+OhFl2p4sKrC3UUkS
         M9I+3KLsoo+JWi7rAEU/eK0SExynUXJazuXOrON7MJ74qLJndWrHIYino9nxrMJTO50R
         sKKHAtQqJTN4L8NwnderZHNP7ezsmm8wQC18i2Zuq23IluP2JzNFrjUN2Za2ed6NWJir
         oamQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1vEdlUvGy8RLoKTAbq/pWstWSgqpJmRqEz58p9TlXEY=;
        fh=9Fbd2gOpLyuUBiqwRggMW48dFFXyItKU9xIk08Ozfps=;
        b=x1lCvuCRseP6fdVrlKVkKduRbuMvFLSuB2CcL5mHLkGAsw/2H0iMFIvqlPP0r3eB7G
         i4I+cbZkr0LQoc6T/LC0sTRs5w3vDf6CeHTjtZWbCHWCx3YG7yrbD0HVa8MjK5ljH/Oa
         EsbW800fc1kfZ82vFbCMZuPZY6g7kNmrQpVdQ+YWb+5xJx+4MhDOAmbBkxP5f25y4aEF
         iwHA6LNUs/hPwg/92vP98GAwoZApVfsmkUc1VpCyzAR634n/GYLiqg0tShsN3PVMUmJ9
         chhKXOfU/EkqpG8Vq0A2KXlroABgN/SnysyvaozUJhmNUGVtcswQBmLzWeCVI++lS/55
         cHVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BFw7cEPO;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708539979; x=1709144779; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1vEdlUvGy8RLoKTAbq/pWstWSgqpJmRqEz58p9TlXEY=;
        b=fppW86IqpciRo3+siRwOLj04VCSXjdXESpDUM/GM0jSQmAP+R41Al4DOPy3+VILvvL
         STCIwxuWYPuuzwh9EhwnE6oIMt5YBNAQhZqBe0xfNwNdjef+b57PFVdLDv1qnvYHwWio
         Kq2y15ih6IAA2aiz/jhB4Nt3OLpbFDoyqWH1EKKLOu64A2gwkkXoU9gcbJ69YlOSRht0
         B8ojqZtm1LNZFINvTlHA6HFsft+Vs66fkac85NCzSe0CZptQMDpMyRY87vXF8arZEK9h
         lVGXfqZ4NC+4E69lvatA+6ZffYPv8NtF0/zWDKjkbkqTDxY3GmbWgnxJlgTqnkA6OMle
         iMgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708539979; x=1709144779;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1vEdlUvGy8RLoKTAbq/pWstWSgqpJmRqEz58p9TlXEY=;
        b=MsnM0hpVpEf3WJPtg3kaKhG67fV0LfuLBeR4UztuEvnCzDTTWYLnsCusnbgUbmYH57
         oyW86fa4d4IlrTIG/YsFArO26VoqBlhEgsq+w0Z8uD6jMZwuH7ooxcCa3ezkWVSmtssN
         j/FkdsXFL3ZTY1PNKe5S6CRXa9I1mwVe4KJ5ZcsFL+DNw2afgWWDjaw8o2Nvbge3XV5A
         /9prv0Vn4YsNi4r2yTaIP9oz7nr17t6EAwVWqjNJENkfffVLn4jf1o8QMXOKLOWyAeom
         Y9wXmv5pe0SBDplaglKSQ+qy6HW/x8BwIvMTeOcz99W5SKX+WRyBstx31eu636hWLVs5
         astw==
X-Forwarded-Encrypted: i=2; AJvYcCVAnkOr8Yk+vdp+JiUeeIW+UFwz61T8GKlamyOlYtPYoE8Pl16qfJQ+xcWCTAmn9IOcWv51HpW8rbzGGEkq9nINIu4xfK8L1g==
X-Gm-Message-State: AOJu0YxhfqoaojsbAgacNXkE4S0Ph6IiC0NIJ1or5S6BvtHBdqinYt81
	50ekEX02F4L0NF0IL80/K2eIaH/S+wKQHBWaKSNs1cKC9cQTz4Qr
X-Google-Smtp-Source: AGHT+IGDgzqcVeaX9WN41s6JoFszWtZ/xO6qtlTN1V5qgwedu6AZqrlF8l3w83OZF5IzTKuQWdHyyQ==
X-Received: by 2002:a05:6a20:d908:b0:19e:a335:84a2 with SMTP id jd8-20020a056a20d90800b0019ea33584a2mr20412515pzb.44.1708539979672;
        Wed, 21 Feb 2024 10:26:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3d05:b0:298:f2ac:c9b2 with SMTP id
 pt5-20020a17090b3d0500b00298f2acc9b2ls3699334pjb.2.-pod-prod-05-us; Wed, 21
 Feb 2024 10:26:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVbeRb/DIX3XRntWzkiEeMgr0Uae51fCKb8UBzH5I5EL+BoYSXddtoqkna0OI7K1KGIhWYTrNwjBn1j7aSar3eGc6pNfe7TH1kWsw==
X-Received: by 2002:a17:90a:1f85:b0:299:9d8:d7c7 with SMTP id x5-20020a17090a1f8500b0029909d8d7c7mr15599189pja.10.1708539978374;
        Wed, 21 Feb 2024 10:26:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708539978; cv=none;
        d=google.com; s=arc-20160816;
        b=csLXthkiaUpa9cPRLajQNKaweka/Yx+6xkNT5tprSiMMxGDvqLpVCz5lblJXwsQqul
         a20Gy+90+D6tSItrZKFtKmC1dra43t5k3A/ddGMegKZjBDAX465hWXCkZndv5BmLNyAF
         /RhQoE3UcGiOLihFbyZblEbLK/baj2Q0EX6OHj3zLon81N1pbJRnD0zUQ/yv1nKACk2A
         XGR4pmhZahP4gJrqqTNtxReoDHjagvEo2/jqBxfea2Zaq0/Y/ubwVcRu5CYtS3nYL/RK
         jltDK27efoaYqHFkc5QWOUuM6JZWygJbIAsuG/Wr3pVcdp9jUeTnfuQ7s7uIi8EKj5g6
         i4uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vXrmA+YUNbHeZInMv385ll0KIlZ9s0pW+epVCXD2DyE=;
        fh=bkQvzrM0YBqu6sBM6TaNZ70bAx42Fj24gATvoEfju0A=;
        b=BJS+ww1QVQQ+6rlXs4C2FkbidhKPAiS1q44R0GunQd3yzaqDne83HzpwGLOe5Rsgjx
         KS4ba0APF8kU9NhJLedz79IJ5/gKK/8Y12q9Ywdy3T27mwGBgFYJMVFvDWNvgUBW7QRo
         5F2rZ0aS3xXllAfrl6oP0XujxJ0vS9//JE3mLVgp8TLO99Pw8rGlQwE9ENJ8iOCaO5b9
         TRF4tr1JYTlb2Jawl9BsVl/qIosd11SNvIjov1BThn6G7v77FZLcB0aGqR4NFKQRQXgc
         bc0asm2Y66GjTk+pKpbTuaOxgv819QxzggIUgdjLbRz+SqkpNypzXUFR43MoJYgYXozh
         4Dtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BFw7cEPO;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id y1-20020a17090ad70100b0029a3c01e471si28133pju.3.2024.02.21.10.26.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 10:26:18 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id 3f1490d57ef6-dcbf82cdf05so1067363276.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 10:26:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX+ouTIrxSgGbVxPqC2I0QM6dPOKEbK7RDEruhN2OIVspdH2D9CaJsn/bCdX/mCFBDbqjFY3wO/HiWUbvT9wfx7VU7bYXY8G4UdCA==
X-Received: by 2002:a5b:bcc:0:b0:dc7:32ae:f0a with SMTP id c12-20020a5b0bcc000000b00dc732ae0f0amr80411ybr.65.1708539977180;
 Wed, 21 Feb 2024 10:26:17 -0800 (PST)
MIME-Version: 1.0
References: <Zc3X8XlnrZmh2mgN@tiehlicka> <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka> <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz> <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home> <20240215181648.67170ed5@gandalf.local.home>
 <20240215182729.659f3f1c@gandalf.local.home> <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
 <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com>
 <e017b7bc-d747-46e6-a89d-4ce558ed79b0@suse.cz> <c5bd4224-8c97-4854-a0d6-253fcd8bd92b@I-love.SAKURA.ne.jp>
In-Reply-To: <c5bd4224-8c97-4854-a0d6-253fcd8bd92b@I-love.SAKURA.ne.jp>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Feb 2024 10:26:04 -0800
Message-ID: <CAJuCfpFyrUizGbS+ZnMdp4-chg8q49xtZgFhejHoSi76Du1Ocg@mail.gmail.com>
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Vlastimil Babka <vbabka@suse.cz>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Steven Rostedt <rostedt@goodmis.org>, Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
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
	dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BFw7cEPO;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as
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

On Wed, Feb 21, 2024 at 5:22=E2=80=AFAM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> On 2024/02/21 3:27, Vlastimil Babka wrote:
> > I'm sure more such scenarios exist, Cc: Tetsuo who I recall was an expe=
rt on
> > this topic.
>
> "[PATCH v3 10/35] lib: code tagging framework" says that codetag_lock_mod=
ule_list()
> calls down_read() (i.e. sleeping operation), and
> "[PATCH v3 31/35] lib: add memory allocations report in show_mem()" says =
that
> __show_mem() calls alloc_tags_show_mem_report() after kmalloc(GFP_ATOMIC)=
 (i.e.
> non-sleeping operation) but alloc_tags_show_mem_report() calls down_read(=
) via
> codetag_lock_module_list() !?
>
> If __show_mem() might be called from atomic context (e.g. kmalloc(GFP_ATO=
MIC)),
> this will be a sleep in atomic bug.
> If __show_mem() might be called while semaphore is held for write,
> this will be a read-lock after write-lock deadlock bug.
>
> Not the matter of whether to allocate buffer statically or dynamically.
> Please don't hold a lock when trying to report memory usage.

Thanks for catching this, Tetsuo! Yes, we take the read-lock here to
ensure that the list of modules is stable. I'm thinking I can replace
the down_read() with down_read_trylock() and if we fail (there is a
race with module load/unload) we will skip generating this report. The
probability of racing with module load/unload while in OOM state I
think is quite low, so skipping this report should not cause much
information loss.

>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFyrUizGbS%2BZnMdp4-chg8q49xtZgFhejHoSi76Du1Ocg%40mail.gmai=
l.com.
