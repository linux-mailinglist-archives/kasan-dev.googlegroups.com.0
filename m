Return-Path: <kasan-dev+bncBC7OD3FKWUERB6UV36UQMGQEOGCJZLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2096A7D5261
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:40 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1c6336be7c4sf1092495ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155258; cv=pass;
        d=google.com; s=arc-20160816;
        b=JvpEKlvaMy8aLFsIxRE9N0PQzdyK14MosEj1KYwQTBpy9CEWHgk/CfkmO8nlXwmQqk
         nglmZ2YksCFBzmTB7r1THXHz8p0ucWb4tuk74Fu7qoP9CR32EKSLp0iZLuJpOtzDZGai
         DjcIM41bgysItKb8cffuKgW2+XcXxOehx7M7fvkGvFo+jili+0aZ3Z0yW8idqDfu8XVB
         ZImf4jK3zC8eCUnJ8kWwtzfut8tf/C4nH4lBoU3tJGBgqXwMxv17MlRVw+W1iuIYV+j/
         uToqsbCUNd+SoB54tq7rZAKKGezAO0djvrdBcZhv+xP1Avn1zB01OJFcVfInQBR1W/0X
         aAhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=1aANSDzJWf7nbWkIlamalwPmAC8+k2EQV1wboowG1IY=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=YhrAnKw2vC/XF5DUr3OEaC4R82dCC8sZs9Jd25+qQ9dCSL9S1pBf1kE74d5k/jMLu5
         GgvZACQnQpd3r6pJIlvJy65ETIjXHx85CRRm1I+p5Gnp833NW6pzdtgcrV7BV1FKqjzK
         2mNfAMelUElQQP9lPaIMdJRNgmmxpZZ360Y3RekFYixETKHAIaOVXp5DP9/Yw5pTNCzK
         95TMR+jWIRfreWJsWS5FcMTe8ggw/Wy2Hb34uBMxnIxm5jeiPY/tZxZZ0wwLuGCGbLTk
         BA9/JybS30LovjJvNwxAEO/GnoxqA+mNgvfobkIODuIpBZ2uCtuJYflirQGovtA+QAyU
         Tv6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DXuINBGo;
       spf=pass (google.com: domain of 3-co3zqykcz4qspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-co3ZQYKCZ4QSPCL9EMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155258; x=1698760058; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1aANSDzJWf7nbWkIlamalwPmAC8+k2EQV1wboowG1IY=;
        b=slsLpRHvosg7C0YT/lpn8+BIR3nxp1eALJt9uKRkDrlOUKm+oIr0WrSrkY0tH6Km3i
         TPpesLAgCIWlqpdPP4RSf/hxuI+J1HNLVcGp3hOtjhAq05EJCNJDLzOpRXN0XDNFt4Ot
         /3UsrwgdHwUC/biJgZabQQynJKG8R/lHA2ktaxInRPaZOlYZpK5Sc+AMsGyNFzbfn3S7
         dTDqM0pNNa8q/81RLJKyeA0BJJpBKsp43MtPniLC3nLLUV6SZPlOJhvMcrhP+fcygNVk
         9c+FU1oQLoepguQ9yKTRDWznIB8XTug0lvqDO9Uft/4rhwjke2yRC9h0fWSqcm9CCdNm
         Jn7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155258; x=1698760058;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1aANSDzJWf7nbWkIlamalwPmAC8+k2EQV1wboowG1IY=;
        b=pgqjjxzP6CqDNR/gFMBkv+rE4ppaCLLBgfiHlLb2EplAsnKkugStToLG6KWAKVzK7Q
         4TKqAoXfgofhWHmr7hb/zT+F9zlCLJw88tSA9H75qWQnlVz0vorA6TvUsFg5Jlxy0uj5
         Zpl1LmJaBuYN43wRmeCDnCYo3laisL6S/DrKxqIrKbh1LXKAEucMVqViehymC4jMzIxP
         FBLbyzByllmHavbqNSHpbn/NyfXIPAwy8Y6P03qUFEt2gGfQSPJRXM2V7SiOEMitYq1G
         G/o9jDXWyMO9WQxVxwVFbnu2EKSJ21DYyj5NKjlxBdOa8vSxSg/iJZzNhqK/+sz2NsIG
         qC7A==
X-Gm-Message-State: AOJu0YwKUPDqNBdHbWkB/AzUwsDWRyXj701kvDb8Aneih8Qby1rWd9N3
	6crUyJMqDidH2KfAGtXJTf8=
X-Google-Smtp-Source: AGHT+IEDyHtFtVBYtPg0vZ8Bgr8w81J8NZmza9gRMtxJFDmza9SZQixLPA4+VTniDRrWQ/m8SZyUPw==
X-Received: by 2002:a17:903:40c7:b0:1b9:d96c:bca7 with SMTP id t7-20020a17090340c700b001b9d96cbca7mr170033pld.25.1698155258408;
        Tue, 24 Oct 2023 06:47:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:d0f:b0:1e9:ad59:9f4d with SMTP id
 vh15-20020a0568710d0f00b001e9ad599f4dls2184244oab.2.-pod-prod-03-us; Tue, 24
 Oct 2023 06:47:37 -0700 (PDT)
X-Received: by 2002:a05:6808:2ca:b0:3af:585:400b with SMTP id a10-20020a05680802ca00b003af0585400bmr12343910oid.58.1698155257809;
        Tue, 24 Oct 2023 06:47:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155257; cv=none;
        d=google.com; s=arc-20160816;
        b=nrtJtuMW3bApwtExvy+lfJHR5V2luvGGq8aT7gcbxyVbmnuCtg9MTEWrADJoHPPi/z
         HG8dmhSCb2cvMHBv8YEBRByDNC8eMZwzbJA6psMDB0JfPIVOn7yW2p25YD+DSOAGsj3e
         /TnQdvZ92D5wNnB7lafmpOwXLi46kL4+NdHPwvVejS1CbGtHMrBMPzobWw7pvdYsOerC
         ntbUvC4CB6h+g1sROku97zIpUzrtQSHbGfOOCXxTCBH88M2rAxcIZTS5+3vN6cejN1xN
         NSGV8iHnXuz1gcQsUU5kgTAYV/oQRbcXMZnPs4fRO9R+/b7sXze/19pJVgTFiYwgyWgB
         65YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=OUWmo6RLkaXHvLlOp0/KP9HFW8MtULS71POlQ8HMTCI=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=Fut2rMhgpa8VCdPkcLAHOwgxKtQrwq3ok6dskBZ4e+osnkZTwf31cmX7w+QjIfy1Ja
         I+I72kHxmmtLYrzcitF9hd4yfHckZ3Bc2mNgf0KKipYUvg7iMk5AOIyqPAXV1rzjlEeu
         uODG6U1iKfZtYSqQClGjUV0EcQE2J73VySr5u1fDts2h4Hyd0E8/D9/7uIEgkEhB979w
         NcjDGESShCeF9zMifS5NYojnYoPv9iItBUalAA7pErehLQEzY8uGIWxt3HS2zCR3YTxy
         RdCng/00KpXd4MKEVB9jNUIIwv0tUoN/iFX8Jp2Abnchse4E/MQ7RgU1CLoFo5c+kOUe
         4SvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DXuINBGo;
       spf=pass (google.com: domain of 3-co3zqykcz4qspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-co3ZQYKCZ4QSPCL9EMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id s16-20020a056808009000b003adc0ea0dc4si741018oic.1.2023.10.24.06.47.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-co3zqykcz4qspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5a8ebc70d33so55477647b3.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:37 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a81:48c9:0:b0:5a7:db29:40e3 with SMTP id
 v192-20020a8148c9000000b005a7db2940e3mr273153ywa.7.1698155257303; Tue, 24 Oct
 2023 06:47:37 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:22 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-26-surenb@google.com>
Subject: [PATCH v2 25/39] mm/slub: Mark slab_free_freelist_hook() __always_inline
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DXuINBGo;       spf=pass
 (google.com: domain of 3-co3zqykcz4qspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-co3ZQYKCZ4QSPCL9EMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

From: Kent Overstreet <kent.overstreet@linux.dev>

It seems we need to be more forceful with the compiler on this one.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 mm/slub.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/slub.c b/mm/slub.c
index f5e07d8802e2..222c16cef729 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1800,7 +1800,7 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s,
 	return kasan_slab_free(s, x, init);
 }
 
-static inline bool slab_free_freelist_hook(struct kmem_cache *s,
+static __always_inline bool slab_free_freelist_hook(struct kmem_cache *s,
 					   void **head, void **tail,
 					   int *cnt)
 {
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-26-surenb%40google.com.
