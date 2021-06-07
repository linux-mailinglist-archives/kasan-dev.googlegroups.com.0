Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMFP7CCQMGQE5KHUFMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8510839DD1B
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 14:57:20 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id u5-20020adf9e050000b029010df603f280sf7813802wre.18
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 05:57:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623070640; cv=pass;
        d=google.com; s=arc-20160816;
        b=RG2QyFFzyWZwljv2B8gcsDnj66zHSpfvSUs05fcdAyvodN6Ltny+TMIAWSNFKgrhiy
         H54mqlf6FW+M3qmXzVnU+IbsWxa6Hb7VszV815vSinpKepmbOMjVF6R023zW7YxCEoqO
         3DqV8rMLpLb/XX5efh5y39AdfJbzYPelPNlOuSCmA5z1zGGmUI09hGe6nI3S+dzj96ti
         ECu1xWGrQOsVrVcgu21CaJl8ggoR8z6GsthPN5lS/4wF2lr5/itJyckqcRiQZBrGP+zf
         BtVX6ZbkmKhAND+xkEp/akXlKK3TG9IdIIW09RmbQ/ADwjFyXO/6FGiAlHY7XF+xgjSv
         8BcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zQ+7iMeiH5vYXlqBMZXU1wiaMd4t7msb8Gb+IFmhMVY=;
        b=k1gpebuMqj0+QK647m0UJZq/uCHZN/Hf3lL4Fylm2OOREqRsgG21Tzw2nKtvyyUbmt
         KrXVjKHxtUSO2t2dRCDBOfIE7mNxL9N/VVvsI6Dnwg4c1F6f7iZTl+zK5Wj93h2LgjJ/
         XK4gLoMe4g5dGI4JBvBW5q1Bsb8UO4tdYrVcFZV4z0uIyw3fYUShqDsQKoGGtH5XXxHh
         Zs9cfjAuUgRLkynnuveJ8MVqrLz/YA0Y+8VhE789xwxa+Yub29528jWCJSNnq+Swpgbo
         D5qp5B2QkEXjhSzMlj6YKA6w9xQdW2OGxYHxkwYPT84W8yFRwehfA3GQryEIRZgkCZko
         hNRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=svdhpRXg;
       spf=pass (google.com: domain of 3rxe-yaukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rxe-YAUKCeIIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zQ+7iMeiH5vYXlqBMZXU1wiaMd4t7msb8Gb+IFmhMVY=;
        b=XmT01YunaQl5Uui/H11w9fDQP2j61EWkvdhNL5xhf2elfueLny+TNzWU6RWaHVwR4K
         JfvMRx1hoDVKG9tv0kmK1sRai37GnyUZV7tzV16NXwjBDlnFldtNpqX7QqiArYzgG0Jh
         byu0bn8s1uqjrE+BqdIyoFTPZX7958H501ll+6RR7OWAa1oe+GDhFovSweph6a2ilXv6
         lh9KpvfLm4+jtw7I3Sy063IpY/9Wb2whDuvndkpaJZfLPumvzTxwQmZT+RRcDDczxhko
         0K1p/cewgKMzNhFC3iOmBvf5QTuUN0JEQgyZrWmOnBWxv4c1xNe4KVFwX0NbjIykU4l6
         rURg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zQ+7iMeiH5vYXlqBMZXU1wiaMd4t7msb8Gb+IFmhMVY=;
        b=l4FySiivJ1LevSLb2Ih7xMFIavH2vtAbKmIMH95JfFaaVmqICa0pSXlZPqHwuCMG99
         AAcWOucfzL27kQBCPlrcX6mRBaG7EP3eLlDmrX409vORcNOM7+XGrQBJv9qtFatkQlzS
         cv4jvpYAteBQW1mv6jHPPb2YewNWGvJTdJNpdc2fE1kQqsbpC7d3PAL5ZcqU7XTH8ao7
         lI2522XAnwBGTxrafog44qWBev+e5ZxAymY6466DAipDtDR81Pf9I6+UYyhw4nyjXJol
         OSyjUVuHfXXtG+3lJ9X1k3qzmFc6bR3cc0MiqkQpz0NVPXySBVT/DesSHxeyuougggMg
         Sidw==
X-Gm-Message-State: AOAM531DDlkE8G6FqVId6p9TvsdO2VSyTAoD19OOB6rc/cyJjVt99M3a
	NJXDS7riDhEjeXPKF5PFOMI=
X-Google-Smtp-Source: ABdhPJznl0hfOn3edBu/VBKBD70Ei+Ad03KaOZ7qdjhCF/Y60RAUAe4G/5fQjjPoZ2mWx06ydYgTcA==
X-Received: by 2002:a1c:dcc3:: with SMTP id t186mr17440679wmg.23.1623070640305;
        Mon, 07 Jun 2021 05:57:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a141:: with SMTP id r1ls1604097wrr.3.gmail; Mon, 07 Jun
 2021 05:57:19 -0700 (PDT)
X-Received: by 2002:a5d:488b:: with SMTP id g11mr16569105wrq.317.1623070639434;
        Mon, 07 Jun 2021 05:57:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623070639; cv=none;
        d=google.com; s=arc-20160816;
        b=CzJEhReGkABSBYsAruemOQavfTrbjR3AdjedgFlWhKhBGrHMmuIJJFjKy4qkN2o9IT
         d9ECPG+Cs16Z088U0xacbD5l2svaLn5a869oI0ewL1S428XwudIYMLzkSFZHQ9RC52ip
         9Xyy7pt2fbbUBaeKn5IXX2H59DZepmWXyW0LjVgsD34KoPU28x2rZVmkV9g/RsyCbsRS
         Rm7MU0J3MjzKmJ96OH+RAamua4yKDrq6Qy4L9OIvB+RhpJVvS7mQQK2rM7ai+RrwtHN2
         X/kw/YdfGutJzJsNSDX1iT+y3ZHVeRMGeYkzP29Y+KeXraSU2jDvLKjAvcYZd1Y6yuty
         X5UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=sD69zNYhvDJZj4XAjsuMed8nmTBfm3+Rx7K2iXla7Fw=;
        b=ZhtqrN7tybkULv0LC1ajNUR/8noslfFRW7yTsfca5nR4kPh9z1uwyhYqhRZ280cf92
         r6g+YlrX2Co2nDofATD7sJVr0cS8bM37loQTaTKVNIrnlMhib7M53MdhG1/8wW6h2/se
         snoNxoQKxfcR5bdFekWRdLsNV6oZbZlaEWZb5V+FujTqrggCpHHQpkA5evja33g1ZmCV
         8Hc9x54391qRbR33FR1a6GNKm5Rn+qv6oFdcPDBzLbgdIYwOfAXY4bH1RQmLU4AEwrT9
         an3h97tumU7HVlAgtvITqMV86pgE1dUfym24cUeGRXjzFLVSZG7uvFuB1OmkwuuimGjx
         VH2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=svdhpRXg;
       spf=pass (google.com: domain of 3rxe-yaukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rxe-YAUKCeIIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id r23si179718wra.1.2021.06.07.05.57.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 05:57:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rxe-yaukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id z13-20020adfec8d0000b0290114cc6b21c4so7771698wrn.22
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 05:57:19 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:2587:50:741c:6fde])
 (user=elver job=sendgmr) by 2002:a05:600c:2216:: with SMTP id
 z22mr13925816wml.66.1623070639129; Mon, 07 Jun 2021 05:57:19 -0700 (PDT)
Date: Mon,  7 Jun 2021 14:56:52 +0200
In-Reply-To: <20210607125653.1388091-1-elver@google.com>
Message-Id: <20210607125653.1388091-7-elver@google.com>
Mime-Version: 1.0
References: <20210607125653.1388091-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH 6/7] kcsan: Print if strict or non-strict during init
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: boqun.feng@gmail.com, mark.rutland@arm.com, will@kernel.org, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=svdhpRXg;       spf=pass
 (google.com: domain of 3rxe-yaukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rxe-YAUKCeIIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Show a brief message if KCSAN is strict or non-strict, and if non-strict
also say that CONFIG_KCSAN_STRICT=y can be used to see all data races.

This is to hint to users of KCSAN who blindly use the default config
that their configuration might miss data races of interest.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 439edb9dcbb1..76e67d1e02d4 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -656,6 +656,15 @@ void __init kcsan_init(void)
 		pr_info("enabled early\n");
 		WRITE_ONCE(kcsan_enabled, true);
 	}
+
+	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) ||
+	    IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) ||
+	    IS_ENABLED(CONFIG_KCSAN_PERMISSIVE) ||
+	    IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {
+		pr_warn("non-strict mode configured - use CONFIG_KCSAN_STRICT=y to see all data races\n");
+	} else {
+		pr_info("strict mode configured\n");
+	}
 }
 
 /* === Exported interface =================================================== */
-- 
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607125653.1388091-7-elver%40google.com.
