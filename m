Return-Path: <kasan-dev+bncBC7OD3FKWUERB2ELXKMAMGQEG4THYHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id DD63F5A6F74
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:29 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id 14-20020a056a00072e00b0053689e4d0e5sf5048417pfm.5
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896168; cv=pass;
        d=google.com; s=arc-20160816;
        b=XVeyfywhcvhgux3iJvR6DFzBqt/l5a6XulOutg7yMUFFzpM0XS+9bOol+vbw4nzohY
         zcMyupZMojOpk5saWDHTmIaq2SVcmwRU/3fC3EOp4Op9jhJv8MmkHmXwqVx1lthR5A5P
         hk36q+GlaxnzI3F0DlfKxMRhNY6BD9tE6i9VSoc6IzbMIxUztFsfgVD5A+KlgLImEVmL
         pqt3spzV4G1wKeFnkn+SCFVeGvo0rJVbkmYGh9W6bVFAhQxCHxuqC9inkLCt1T+LHN2E
         8+z2fcgWUAGtFA9RlCVw7uDSKRNPcWDmc4xviIlI7sgJttctqFvVi4IkvJq7cnStGhkV
         pzQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=q5ImXJNJnMSvL5St3lHv0KGUzDB8AlTxNoXZ+wzFMwA=;
        b=V9zSGv8neQoyCjxYoOja5YVBIi9lGTyiILIvax2wwnDks8KRZd9B6QD65OfDxd6XFz
         6jPRJD+gW5Kifg+r8X9bs/aYmyhClUhYGqHASWoIICzVFt0jsW4Azo1J5Ko/3BPB+j4G
         EcPDb8GEOBfvVXOnhNc1RfBHiUWqdpgKKorr0KTQTjijOMHomMCYdkxG3oJk74BafEmh
         ksekRtbdG8RVsWC9qE5tiF9xa1S4VKjYXCUzpl2DHdFcc3X0dVRi8MReyFK4hqxryjCM
         BtAWVyr7K1gBeONcmM/e3Wuy0TH1LK0tPSSfWugfcHwongF7IqNAvb7yD0twVHgYBu7S
         yw7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=B8JrbzRl;
       spf=pass (google.com: domain of 35ouoywykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=35oUOYwYKCUs574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=q5ImXJNJnMSvL5St3lHv0KGUzDB8AlTxNoXZ+wzFMwA=;
        b=f9eEcf6jn7qmivoyr5cjJpblql0V0bsFhfQoPQpHFsXoOSCPxhkHU36jlXWBQIXp47
         GLSOqPlFXEE8pjjGwRxsWEEdndkL9LzbVIruaCYiHaVbixwbTjC/xikMX+K6duDnRzME
         F6aU1DYQiIfSwCpH5w/LrUzD4JVNgadcGZCJy4ze0S7GK5hwZUF/y//PhCxMMgCBHqA8
         Pt8V+E8hlSXlvQvojlvyCDdd+tW6gLl+d5fsmyEa/qFilPb9pnvugysKQbPfgUDjmGp/
         R7hpmCWshZb2cVkplaWAF4M4G6Koq9xCbpHVQJ36ihGKiY9AuoIxwyJw+2+MAAC7FsuY
         1ExA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=q5ImXJNJnMSvL5St3lHv0KGUzDB8AlTxNoXZ+wzFMwA=;
        b=TeM5OHse3XroS52+MwRJeYa8JpsBbzAR4zdVELRFKZkzLMzuzGjU4+W+IyF4XHn3kk
         sn3VTd4L09xdVXwAVHWpaa0tWjgTZoMeVMfODfh9LdzXSHWGUo0m6e//Ht5sCmfJIEY0
         SfH0Vdhm/eb7PaIftsgHLFcEOqFEZseE9A7dvu/F85givkLwCQfIxXLIfZyUJeXrDDR2
         H7AzYpXhPnucul9eMM/cvgomCkGiTgqLkKrDsK5CnYE6NM937Y0eGDoGP99+Jk4gwAQF
         FkjJzA38rXqac8AmiWiCrp42cVWC277tVL5cYUYJea6I/3p4v4x1jivW6zZnZiTe7jgH
         oN4g==
X-Gm-Message-State: ACgBeo0SKgLE9zY5Ywvb4Y5NlV/94h3ZZlO7u+Tzi8QESBG1KNFzi0Fb
	d7iNmyICOq9qkVrjxycHV9A=
X-Google-Smtp-Source: AA6agR65uTBOS6NYSq7jXwU2KsypXJcTozRJRvx3E76yovY8WCxyowLIZLv/4v9PSbj/jMG7ZszCDg==
X-Received: by 2002:a63:f304:0:b0:42c:1057:e37 with SMTP id l4-20020a63f304000000b0042c10570e37mr10062783pgh.379.1661896168169;
        Tue, 30 Aug 2022 14:49:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6f41:b0:1f2:da63:2f68 with SMTP id
 d59-20020a17090a6f4100b001f2da632f68ls2269264pjk.3.-pod-prod-gmail; Tue, 30
 Aug 2022 14:49:27 -0700 (PDT)
X-Received: by 2002:a17:902:e547:b0:175:376:875 with SMTP id n7-20020a170902e54700b0017503760875mr7033395plf.147.1661896167453;
        Tue, 30 Aug 2022 14:49:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896167; cv=none;
        d=google.com; s=arc-20160816;
        b=uj6Cz8TU3ixOYok3koxrpblDsRjQkBv9bA73Cggd/hAl83Rr/YvP4Xzb1qPmzq98Lu
         scEu4Ni0VSgwvd0z9++PXc/zRm1M7fX+O6m8VEzERCTw02TQib5fNmOlf1SQvwQwhUy5
         CDZ6AM1W6KbfGXtc88ZHUtfJbcoGcee9XvzTmc2fMZJXLLyM5nkBJTS25rLwahgwR57X
         A+HY6WDo+US1fJPlLNNghNYgGJM9KdHCZgO9/vC03fEavMlKG7hgUDhbcMlzjKA/LU7B
         gu45rSm72j3d3wEMf7J1F0avRLFie2YdYaUaOTX8jeugJEu3BRA8qhvRqRJbuaEleiqv
         1Wqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=b8cpW+nrR3APd+B9XZ294x5uN/r70qZMashrRw3GaA8=;
        b=aHjpRwaa9UDVR6Fu4hfOOriYXTdHPwhEWU23OuIQawDSe9UjD3dw14E2BcKa23Y1fM
         tjPc+a1/uFKzJSLhsM7ittg1qpNiJJ4YLZMls1nG3V/e2/ZCzMJ5PiPlkYxACjKh6rV5
         CzHO4hZ2fJZgtEYE9NWtQ1Uf0gLKhdlaWhXfDTRN8vqg+aXizDN0760eoxm036+UuQD8
         tw6Pvf6qQlNiUaBgK5KcNU09tNBgVe8TC+WUCfpRKlTfgraeYkVdQf4A6o+T2ogACufb
         YdRUK5QmncpagPuuJ8EU9Zt4hpQjDB91iLJ5tGSB9Qwxv6drbaC2Dn0iLRmo7vOXGpxe
         BhbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=B8JrbzRl;
       spf=pass (google.com: domain of 35ouoywykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=35oUOYwYKCUs574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id ot13-20020a17090b3b4d00b001fe0d661525si4785pjb.0.2022.08.30.14.49.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35ouoywykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-335ff2ef600so189306937b3.18
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:27 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a0d:e650:0:b0:341:85d:f480 with SMTP id
 p77-20020a0de650000000b00341085df480mr9713169ywe.161.1661896166926; Tue, 30
 Aug 2022 14:49:26 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:50 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-2-surenb@google.com>
Subject: [RFC PATCH 01/30] kernel/module: move find_kallsyms_symbol_value declaration
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=B8JrbzRl;       spf=pass
 (google.com: domain of 35ouoywykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=35oUOYwYKCUs574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
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

Allow find_kallsyms_symbol_value to be called by code outside of
kernel/module. It will be used for code tagging module support.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/module.h   | 1 +
 kernel/module/internal.h | 1 -
 2 files changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/module.h b/include/linux/module.h
index 518296ea7f73..563d38ad84ed 100644
--- a/include/linux/module.h
+++ b/include/linux/module.h
@@ -605,6 +605,7 @@ struct module *find_module(const char *name);
 int module_get_kallsym(unsigned int symnum, unsigned long *value, char *type,
 			char *name, char *module_name, int *exported);
 
+unsigned long find_kallsyms_symbol_value(struct module *mod, const char *name);
 /* Look for this name: can be of form module:name. */
 unsigned long module_kallsyms_lookup_name(const char *name);
 
diff --git a/kernel/module/internal.h b/kernel/module/internal.h
index 680d980a4fb2..f1b6c477bd93 100644
--- a/kernel/module/internal.h
+++ b/kernel/module/internal.h
@@ -246,7 +246,6 @@ static inline void kmemleak_load_module(const struct module *mod,
 void init_build_id(struct module *mod, const struct load_info *info);
 void layout_symtab(struct module *mod, struct load_info *info);
 void add_kallsyms(struct module *mod, const struct load_info *info);
-unsigned long find_kallsyms_symbol_value(struct module *mod, const char *name);
 
 static inline bool sect_empty(const Elf_Shdr *sect)
 {
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-2-surenb%40google.com.
