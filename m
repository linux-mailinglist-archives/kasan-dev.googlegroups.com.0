Return-Path: <kasan-dev+bncBC7OD3FKWUERBRG6X6RAMGQENQ6PGLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 834DF6F3401
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:37 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id 71dfb90a1353d-4405f56df75sf2207229e0c.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960196; cv=pass;
        d=google.com; s=arc-20160816;
        b=lz+xs99SocvDGWMJ6vXxpBEkaPGNWqjDTnkaMo683Mm0LMdkyS4vDZ/lKZO6eWq8RQ
         ZB1covn3ewWWVnxM2tWq+MorabOx625EzOqNLGf03ZJcXcne2bMSgoSkmLd5EYn7EOcg
         TmVhvYHp9AiCbELnbL4D7/OIpNM9uLrGYkdvWMu1maP0DZ0IPj9LAZz8diwAOY8YQb7V
         teO+gvpK+eeP8LGUfMAaWLOvLUYZW2BINqGkxX+Z/neK/k4Z0fULxwmfGUkBRKPhi6f9
         SklCfkaKy01/MC7qkeljWdQIfDJuLOIxUUhpRtF6CvTvznF9x2WQrGjpdR6VyBVXSJVl
         1Qhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=HQbNPisblf7hJd/f+aZPEFoZh12B+dcMLIbSUasvBno=;
        b=SANDuzi/l1xyaKECpiAEtSgUUrh7DetAz47eVplkMnx3T/VGGSx+V437Zd2gyuGDv3
         h2SYJkNzEolW+GQmdYGEEPfH2PBVoGW8MREhUQEnSo5VixftoyDHvxg4IDcQOcZKV1oU
         oftURKk17R1ccSTM3PtGFOcaXxB1uyQ9qxePMRTaLYlDF7QHm2prPc33eItRFJzm3vmM
         7yzGTpeMkG18hAOE36f3UExPEOM6qQZhWhe3o8Hmfymshb8INm3XhVU3sIKbOpOTX+ZF
         VHRqnW1Q2kV2ftM1KJ6Z4Ozg2np/x4cH+80rsxB/fWPFiExurBn3THTKIqd8tSqwLBiv
         8p+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=cL9ulyr1;
       spf=pass (google.com: domain of 3qu9pzaykcyk574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3Qu9PZAYKCYk574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960196; x=1685552196;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HQbNPisblf7hJd/f+aZPEFoZh12B+dcMLIbSUasvBno=;
        b=GyfCKQHIUZkt2dyJwZ+EcmHI7jvdTsyu2N+SsL9bpY6VbuYcH1mKpA9EnNbYEqaSR2
         VvOyGIvTK+46eB/RH15k0m1MJQI02WIWO1F2SaCtmSw51h2RTnkZfCQjbfRlQ04IzDuf
         PiM8sr0GYNQJxHryC0/r1EzgFlw8c2fhs7WTN0X3S+J33SPzUuuwiRNchNVXTuPHoPnQ
         sUz/1xx0zN4XNHhM7jT1fVeDSPGlQUUk3vzdWsO72Nyzz7+tBfadgGBIy8ArBap8SjTi
         sDyWrVAYYDw2bhLBdrpykxGeIS+EYy3cqWoEXZbt9PQ3smqfxV2Bb5nhjsGhAEea1aB2
         EC0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960196; x=1685552196;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HQbNPisblf7hJd/f+aZPEFoZh12B+dcMLIbSUasvBno=;
        b=gW/HqQpXBprc0ilLz2+2KPfDaWtLPPrp4KRSQ5suo2b8zBclQRHE6JqCEOW9BLJ3iJ
         hk9Jf9bew5MhfWrvPp/a4fXP0TkfI6q0lioTc3tDKoGVbZwhCIhp+gihhpRbU+5sn3CN
         L/1Dt3bCVuHBgmb8c8Fc7Na9SP1YzPj+mvp4N2X8UuHKzcXZ9YicFSnYwDymZANSRgXH
         JcenwNkkra8/OiZ2ktpAG2Dtd+zUETJPmn2mKpRKRnlY+W6DhSZQ4WpZyyddv6sDjVzF
         2qdFrI+z7w1g6sLtO8gEtgq8jcLqgaK6dEzFXH1KgonErZ3IKgA+sizyJvydkUX9iMcE
         BMww==
X-Gm-Message-State: AC+VfDwtCYXEZfyHwlszwF3noLdguR+7zLGak6DE4mQVQrmhyFqpBUla
	oQy1I5gBwBnlASix0/iPvSs=
X-Google-Smtp-Source: ACHHUZ75LU+D+SDchMRPVPRBQbnF6bttK43vKiPMljRqB6AYySScTMtcVE49jLyTII7OCNPBEbeTgA==
X-Received: by 2002:a1f:a012:0:b0:440:380f:fc20 with SMTP id j18-20020a1fa012000000b00440380ffc20mr6841433vke.0.1682960196473;
        Mon, 01 May 2023 09:56:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3f54:b0:426:b068:aa4a with SMTP id
 l20-20020a0561023f5400b00426b068aa4als2747826vsv.9.-pod-prod-gmail; Mon, 01
 May 2023 09:56:35 -0700 (PDT)
X-Received: by 2002:a05:6102:2751:b0:42e:63a5:b711 with SMTP id p17-20020a056102275100b0042e63a5b711mr5504847vsu.10.1682960195821;
        Mon, 01 May 2023 09:56:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960195; cv=none;
        d=google.com; s=arc-20160816;
        b=Eoo8ZOnbVE9tEi3d0yyT7ngrza5W7Y308JTs5dh/7bHa+fEqbxLosW7Ztejnw0dWR6
         KiHzpXIBWIxm4tGPao2fHrK7tEzANNHO5GOFGQN3KtqqTfMa25dNlZFQPfYHEAoZRQDL
         rUQ01941f+07siOKDxtyMF8pj9Ac7mND7nFY7qBMVC9MQzyd8jjs73VAS6GxzjWqJUIR
         hK7g1rChrBoXMl0tdCyZPuyuprtWHNbjJ9xU7npRmWkl2UrkzCyXVU6mRGnnSPgsq7jI
         x55lngXvSWrO8yG6akgQeIKluBn5SCelu9nNpSHqlNkGARM4zwIKz0t+QZEPDjym8R3f
         8ZZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uHz3gIMQ14LMAlJH3BHlupoStZ8/+BrUL09pT+1nDVs=;
        b=JR2fsnq0Wsuoouammhxyb+Vf8V59xv/ihD3yh5S0QYTeXz6NHGCBZKATkswSabU5UZ
         dCazKSjM3nfWCpAIlKRgyt7bluCfQXZpPNn0OWiXhwI1OFHvKS3zHXu1aLqqeVFufs+p
         gMMcGVpz5jEXzpmeqhZ1pysb4DllFcix6lj/adJxQPfFl2Ga/cjpuJdPyx+OluwGkL5n
         oBSXvSnyhEYa+40XNi2PysQbfe9ozwn3q8p1NyECGzSk/x9BtZLt7XxVuzGW5Z+AvG8W
         EwSUgGlbQ+FCo5fTj6l2Tr/L0CBKS/rrD2m+Kj7oXjgTE7m5LSB/ftcVCFg+GRpdvjxR
         YeJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=cL9ulyr1;
       spf=pass (google.com: domain of 3qu9pzaykcyk574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3Qu9PZAYKCYk574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x449.google.com (mail-pf1-x449.google.com. [2607:f8b0:4864:20::449])
        by gmr-mx.google.com with ESMTPS id ay20-20020a056130031400b006903d74ecf9si2023524uab.0.2023.05.01.09.56.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qu9pzaykcyk574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) client-ip=2607:f8b0:4864:20::449;
Received: by mail-pf1-x449.google.com with SMTP id d2e1a72fcca58-64115ef7234so23372367b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:35 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a17:90a:5105:b0:244:9620:c114 with SMTP id
 t5-20020a17090a510500b002449620c114mr3673305pjh.1.1682960194723; Mon, 01 May
 2023 09:56:34 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:48 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-39-surenb@google.com>
Subject: [PATCH 38/40] codetag: debug: mark codetags for reserved pages as empty
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
 header.i=@google.com header.s=20221208 header.b=cL9ulyr1;       spf=pass
 (google.com: domain of 3qu9pzaykcyk574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3Qu9PZAYKCYk574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
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

To avoid debug warnings while freeing reserved pages which were not
allocated with usual allocators, mark their codetags as empty before
freeing.
Maybe we can annotate reserved pages correctly and avoid this?

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/mm.h | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 27ce77080c79..f5969cb85879 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -5,6 +5,7 @@
 #include <linux/errno.h>
 #include <linux/mmdebug.h>
 #include <linux/gfp.h>
+#include <linux/pgalloc_tag.h>
 #include <linux/bug.h>
 #include <linux/list.h>
 #include <linux/mmzone.h>
@@ -2920,6 +2921,13 @@ extern void reserve_bootmem_region(phys_addr_t start, phys_addr_t end);
 /* Free the reserved page into the buddy system, so it gets managed. */
 static inline void free_reserved_page(struct page *page)
 {
+	union codetag_ref *ref;
+
+	ref = get_page_tag_ref(page);
+	if (ref) {
+		set_codetag_empty(ref);
+		put_page_tag_ref(ref);
+	}
 	ClearPageReserved(page);
 	init_page_count(page);
 	__free_page(page);
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-39-surenb%40google.com.
