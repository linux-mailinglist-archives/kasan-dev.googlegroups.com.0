Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CCC5474D88
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id a64-20020a1c7f43000000b003335e5dc26bsf11832759wmd.8
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=ywyD9iwyImeVrEXz0kxz7sV0vnnrRhG2MUGj4zBvXw7vxOKKKUpegOJmQJlGkSJRFU
         krWJTi/gBNa2LTvSavkmZN88bBHcRzYuv/RDQeoit4WhL2x9WRIbLEAeL1LFskfwLv4N
         ewhto1nG/8LEotlnf+hUq7wm08FSSMML9ulXQyTzNDqfDiybjKxuZCoGuIzA8JiRe+U+
         C2/WPnzFtlEu4OD9tq/SpC1s1dl+UIK+1ZRcMv5omAAsz6CBh3G9ZtjSfvVFUbZ8Jfjn
         DXZ6k5wvJPEaW7DrZrE87RAUbJaif5JHrWhEzxpt9ik1kxt4i+/m3Bh1EGbKXm5qB7FF
         oASg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BHLYwrUMNhBQr8YujMZglL61NDE/NLTucxcUz8l5Af4=;
        b=ccEZNDCbcvfXnHpHu/oB2lcq7EWw71RbDonmzqDLJfPZnm9hXhJJUpDXec31p/UMhr
         d3YLNTxKhpEaah9zVP0z/jnuZ4WSgWCJ71Y2JYFH/7XjI5gm2A3fvFTJj9BfXlq0YSr8
         3sBkkguLU/wuTLtlE2l1MP4XykOgUMljKhm77zp3BPbQnZCcCrQSmnQTLTQ07rK+QIdF
         DhIy/Ov4j91fEdszXeA2MAu/Jr3pgqpsE8j92E22ZXUhXmwc5dsIwhKogMjDdv90qFyd
         D7fCvSW1g5HTRxXlNP8o3cHHa8FKqhvF2hVFd6XdQfPBazsCe/NacVraQavTXmv77bmY
         arUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YgGvLEFM;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BHLYwrUMNhBQr8YujMZglL61NDE/NLTucxcUz8l5Af4=;
        b=WEuLY328+nEKR2U3BHme8dDgaDnHYggM/PlqxApQDn6wC2DYMWWXk8Xg5Su64BpymT
         vYIs5ZmTUp+wbXsWeYBJEqCpcmKv04Gpd466dgpEzW6i05FzQkIXVjSjZ9EeF8+mpaDn
         ydBA4tW3IDsUl8W80Fq043Tq+alT4sIE35h86chRe5DsOoukA/brHxJ7zLEyI4PgDVYi
         LXDLaRymPee4HRZPPS2YBcNTLMuwje5tsj5S/+sWfPC6q1lh2DepuHK9Xt6XN5sYdWhn
         rpFEyz+U/5IxojkVmVnxLzL/xPFXAgo405ZKIu9Nn8rdNV2ssNtr7ou87jFO/DPndtpJ
         ldbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BHLYwrUMNhBQr8YujMZglL61NDE/NLTucxcUz8l5Af4=;
        b=XqZNGo925l2E2EQ2p6DYNSdf+zS4dx2oPnNGa1rQc5bugmYbj8AICuIdQKd50F1/ml
         NJgz+IIke/JVAiHm4DO8hxs/cRxd3LFe2Zvfb+Xo7Iq+2MfY0B6IQf6dW3LbHrx5WRrq
         x9hXCg7gEOm7mGmjRjJ0yD1oJUHZ4LAbIY45MFj8J7OcfM9HDEqTOsB1q/5PmBEx0rXI
         Dq78v+oIjzBI8KrpylSIl95VX5SlPKVLT9wqIlA1pkl96wmxWG7vNsfLNBRVdeWYOXz7
         H5XABVHKABMG5VPpf+26Z4/YXY9o1iv//8hl9igyTr8XJpdrb6fMoGrps//RXh8ngW65
         VjgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53099oEejWVuH+gQ30sS0WutNMCU+UFhnQGK/Xw3Visp+EjMKfWV
	peR/GTO8r7cwSioveD8VgVg=
X-Google-Smtp-Source: ABdhPJw+cagJPTIRa57CsvEFe7GDAxhOtkaTP0t+QPDU5S9wcryUV9rBxP7f2ndGJKHkC/sTA62N4w==
X-Received: by 2002:a5d:4408:: with SMTP id z8mr1712835wrq.551.1639519486899;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls202867wrb.2.gmail; Tue, 14 Dec
 2021 14:04:45 -0800 (PST)
X-Received: by 2002:a05:6000:1548:: with SMTP id 8mr1703192wry.279.1639519485906;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=gqToNsDaFDn7MOlW94s6U/TD2URe/QwGEovl8bhmpymGV9ccuJQabzJSZ9LJUhqs0/
         moecuSCrWzpqVSsoOOu0PNG0rW8WaHrcJkOeCmeIsuqUxIQ45R4mcrFMXIsS2SjWsyIB
         tIKW0P7/i6z0sMpG4fQs2BJGu9HkWMMm/WP0fzWaO0DDqnYAALdcQmO0sUbpcxpMBcGT
         5+LviRPrdiVbeYeTwCQ6KQbvW6FhiUs2W1vQlcX4rsqOrsIYeVSdlH4MkeIlqUzc/y+b
         qk0DyqDmzP68qR/zt92HKuKA/Ka+t36U3gaKt7MtLXcvJpmVDozq0Co4W8ebJCqRWY/W
         WNmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sXkUkf8VYGGt8pH6lzflZjvDhZhIHUzE6oBqQPaSfN8=;
        b=WHIzNEsDO+NloO7ihPsbeyxwJZv3pGmTatT++Jr24i1ytVKyOVEfWqPhThbacTNd2v
         LZlUhbcSWCO+GuxBezb9HOSOjm9a+kZ0LRiVEu5BUHFPjJEB5VCaYJBFHS8X/yfPTwyp
         BdSsHuGm6DlRO5t8ww+x2iDYkOGfzfQzXJx3AeaW1vzzcibwomTRBhnV3lECIkx1IPcC
         chlfqGK/Whls3eUdpk7l8qHQk1Addy2/YgC897I5kdtJqrNPyE3nLetjRKUit9ZJYW12
         fI4QcT9c/jbNPUYfcqg5jwTxw3dJ3PckoFcjuFGTHyc6nZxQ6pExCO59KKvmjRLGD59a
         BGvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YgGvLEFM;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id o29si4791wms.1.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 26E2761720;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2C284C34636;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 80C0A5C1E84; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 20/29] mm, kcsan: Enable barrier instrumentation
Date: Tue, 14 Dec 2021 14:04:30 -0800
Message-Id: <20211214220439.2236564-20-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YgGvLEFM;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

Some memory management calls imply memory barriers that are required to
avoid false positives. For example, without the correct instrumentation,
we could observe data races of the following variant:

                   T0           |           T1
        ------------------------+------------------------
                                |
         *a = 42;    ---+       |
         kfree(a);      |       |
                        |       | b = kmalloc(..); // b == a
          <reordered> <-+       | *b = 42;         // not a data race!
                                |

Therefore, instrument memory barriers in all allocator code currently
not being instrumented in a default build.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 mm/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/Makefile b/mm/Makefile
index d6c0042e3aa0d..7919cd7f13f2a 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -15,6 +15,8 @@ KCSAN_SANITIZE_slab_common.o := n
 KCSAN_SANITIZE_slab.o := n
 KCSAN_SANITIZE_slub.o := n
 KCSAN_SANITIZE_page_alloc.o := n
+# But enable explicit instrumentation for memory barriers.
+KCSAN_INSTRUMENT_BARRIERS := y
 
 # These files are disabled because they produce non-interesting and/or
 # flaky coverage that is not a function of syscall inputs. E.g. slab is out of
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-20-paulmck%40kernel.org.
