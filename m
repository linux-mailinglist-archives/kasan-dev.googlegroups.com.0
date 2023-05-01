Return-Path: <kasan-dev+bncBC7OD3FKWUERBBW6X6RAMGQEOMMTMTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D278A6F33C8
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:35 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-6a3fd9ff448sf604444a34.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960134; cv=pass;
        d=google.com; s=arc-20160816;
        b=yvpcD9SMiDbEasPzJZxuPzpleJiP8PeVsfMvBLfuHGIgl0j/F33I6wrJ/MJJ5xVrq/
         v+Oo6EtW0qmHH3y0HWNDmxLxfNlfQsXN6d6DZ0EhVPITmc8S91c0hP4/trkR+OMhq0Ic
         WV7lbDIX2Fc9rgbB/6fm2Pt2jWv5J8kL1Stkaj3XBXMxo8rDfYLpdu0BKe+nZMKIY4M1
         uegqZstc6jqjXPzCQi6j27PF5Sf8s8YsL2ygKs6YgAt4U3zq7PQXYRVSF1ZCjVjWHeQ4
         N+abeqZN5Po69XukUNVmcA/PdbgOGGj6XV4ktYWqr0NUjDqXrMS3G0YZAWULwtPqj8a/
         +o0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=8Azk94lhaVLaHSvGaY/GjDPNHsDu4qxRDPxpG+MH8P0=;
        b=LZPTi9HXnQFgOQNl0cSuUNdlfbXDR54dkHKMLLlBx04oJx+bdBniJF7X9feYyOfB1O
         KV0oJ5rMeVFVfd52r/oXpWt30ohSUiWpqwJ1yg8oo0TO6QP5eoMoBBDwyhYv40F3b5u+
         lC+G4VSFbmzmPNJou3uJ1kfRAD+FK5mL0raUKH1FK8zhVP5mWUsLs5syOpmdBskdnALi
         l8wZpDJWm3ssbAxL4agX8rPN2svZ6q+BUw+lp0HOqFY8FIAU/GTLFarM5t2fnt+Mtl3P
         fRV0MTR9J/JfD3rSzDy3kFqwzh5ECRCLwH9T+b4onuqy0MMsKFBJ6Hw1lsS13gyjjiSU
         eymw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=tJm7WR8A;
       spf=pass (google.com: domain of 3be9pzaykcuw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3Be9PZAYKCUw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960134; x=1685552134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8Azk94lhaVLaHSvGaY/GjDPNHsDu4qxRDPxpG+MH8P0=;
        b=WLRnWwuTl4zwvYskwXuBJyCBUeVV1387d4xYkXpPbfRcUSrsz4diqQh2zV3NkeRVvu
         Pfx+BAhGW965KYQchWa1+/phQ8AMEIjduSRCV6mo7Ob1Gd6tcj0IivjKtRVqcv8TFgvR
         xfq1MVRU9ETYbAQVnDwH+/ORAoy+eYtriVZYh9dxHDdzt60ca+rtvOQFWiV4o066Q58L
         r5SwtXGpgG5/EoBDQ0+uUUfBciWHhZUecZ7GCwEClfdzAAEchKhUN0TvHTuz7pZajJX7
         EGvOqyextoNcp/Dq+xCln3r4ccFECnz4ky2ICuwxkjRJUKQYHbJyE7boXmmLC9V2uUXO
         vhkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960134; x=1685552134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8Azk94lhaVLaHSvGaY/GjDPNHsDu4qxRDPxpG+MH8P0=;
        b=bIgdDSMZFcYVvYhWEHs1bJ6Wv+OnUgjUC7XdgPcMFwRcBXh0qwCRIquQmQraujKy9x
         C9zXEEq9dDVYTggqfLYNOOtnsZwTuXUAoUzpZFTlKQEL9xD+qqfNiat9QFrppziiyPCZ
         dDyFUkqEwFl2kCH+O+kwBZqER+Txs2ndTTY2+5XctASa0rSIEZMCnFnAbIlo8Ss2fbRt
         YfUFxMFRPVXO73g+QNH6+24WqYofA7c0368MF+IIAwyixCqKpD2cF0J3CPhHrTPuFnXr
         wS80tmgU3wLVqJC91I5ATqDAM5vTeKcfshK4ZUiHb6RVw9sdC52m9XsGfE1/ucuKn+3G
         C0nw==
X-Gm-Message-State: AC+VfDzm6gNZtlV/J5Lif83Yfa7t1TBtn4IX84uPnJpG8v08L9lZn4Y1
	+F1YodbArD1d0GOzPfb+UYk=
X-Google-Smtp-Source: ACHHUZ6/ba9AGfzaYemJuzvBDOsP/2IUAHHGdg+PiDsbGoy3Bb3hWsK8UT7tpQxGVY0EEU4SMXlJgg==
X-Received: by 2002:a05:6871:4186:b0:184:806d:12d5 with SMTP id lc6-20020a056871418600b00184806d12d5mr5392321oab.1.1682960134737;
        Mon, 01 May 2023 09:55:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:de17:b0:18f:9d2:8d6b with SMTP id
 qg23-20020a056870de1700b0018f09d28d6bls3326277oab.7.-pod-prod-gmail; Mon, 01
 May 2023 09:55:34 -0700 (PDT)
X-Received: by 2002:a05:6870:e14a:b0:187:a540:5b3 with SMTP id z10-20020a056870e14a00b00187a54005b3mr7505549oaa.37.1682960134348;
        Mon, 01 May 2023 09:55:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960134; cv=none;
        d=google.com; s=arc-20160816;
        b=QgRhzYvuqfQHCeA4U+2WorZp0w/PbRprSdV/Wq4SlZL91hoCZZl8c7Stk+rBDBxjEu
         MdNfZ+FmApaF+Uu4mQUbNscJDGnV65hLhsXmnmoxoUaBbx2WFf+pGfoObXc8zGuR8cNR
         cyRPE1TTDEnNlrpnu9gl3KtdrDXuYoDJgw5pS6pLHX0XGBb79+rW1fld+Xzo+yimWgbU
         s1E2+TDv04KJUyem2ur33WQGknHWg+A/nKGHBquA1mk+76CiecR6saJctTjkdSK7GnSp
         w0pV+f9calw2K5BvmiiAw38hisXSnED5LWZaHh4Lc0vjIorEwksYp92dHwhL5VCYDhBi
         mP6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=AxHF9zQp9trScXtaAl0tt4NG3XQrBAxJQ/ayq1tkXak=;
        b=QHuehSFOyxeaFShbhxT3bdc1bnArqfK/VHYThNakQk7TxG9nVQqogo2q6iWJzP25fU
         afnXlLodYZFUZjo0KhtgEgpeqW/bGSzpNu7vUxxMxwhx0YrX8zZyBoT/cxVa6Vkerz+U
         rysPcokg5DLTN52Hs6zG4xUgaRVYGmlmwE+3sA1IttqcVtejOGpkkQZwMThMYYJL4I5g
         l6u5dMBfqUdTDXQdqE5G4ziybh02OXcHG7XW+Byjg+XjfVNpAwURxKZdFJ0+7Yz8ZPQ2
         MhSnIYRXh3KfFnP62HV3Xvd7tkEtSHUa9/2+BlY4cY/NSjqRL+QxIIDcjw6gGYP3okw3
         QyIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=tJm7WR8A;
       spf=pass (google.com: domain of 3be9pzaykcuw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3Be9PZAYKCUw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x54a.google.com (mail-pg1-x54a.google.com. [2607:f8b0:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id gy16-20020a056870289000b0018b18eedb62si1829110oab.1.2023.05.01.09.55.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3be9pzaykcuw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) client-ip=2607:f8b0:4864:20::54a;
Received: by mail-pg1-x54a.google.com with SMTP id 41be03b00d2f7-5144902c15eso1412446a12.2
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:34 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a17:902:ecc5:b0:1a6:6bdb:b542 with SMTP id
 a5-20020a170902ecc500b001a66bdbb542mr4742101plh.9.1682960133566; Mon, 01 May
 2023 09:55:33 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:21 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-12-surenb@google.com>
Subject: [PATCH 11/40] mm: prevent slabobj_ext allocations for slabobj_ext and
 kmem_cache objects
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
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=tJm7WR8A;       spf=pass
 (google.com: domain of 3be9pzaykcuw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3Be9PZAYKCUw685s1pu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--surenb.bounces.google.com;
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

Use __GFP_NO_OBJ_EXT to prevent recursions when allocating slabobj_ext
objects. Also prevent slabobj_ext allocations for kmem_cache objects.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 mm/slab.h        | 6 ++++++
 mm/slab_common.c | 2 ++
 2 files changed, 8 insertions(+)

diff --git a/mm/slab.h b/mm/slab.h
index 25d14b3a7280..b1c22dc87047 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -450,6 +450,12 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
 	if (!need_slab_obj_ext())
 		return NULL;
 
+	if (s->flags & SLAB_NO_OBJ_EXT)
+		return NULL;
+
+	if (flags & __GFP_NO_OBJ_EXT)
+		return NULL;
+
 	slab = virt_to_slab(p);
 	if (!slab_obj_exts(slab) &&
 	    WARN(alloc_slab_obj_exts(slab, s, flags, false),
diff --git a/mm/slab_common.c b/mm/slab_common.c
index f11cc072b01e..42777d66d0e3 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -220,6 +220,8 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 	void *vec;
 
 	gfp &= ~OBJCGS_CLEAR_MASK;
+	/* Prevent recursive extension vector allocation */
+	gfp |= __GFP_NO_OBJ_EXT;
 	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 			   slab_nid(slab));
 	if (!vec)
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-12-surenb%40google.com.
