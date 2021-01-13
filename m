Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMF47T7QKGQEWPGZRTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B71882F4FCF
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:22:11 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id k16sf1818220qve.19
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:22:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554928; cv=pass;
        d=google.com; s=arc-20160816;
        b=i7eKWjfOqJAMThcFu3VFvXLSCRXhbbAEIULm9wXUaVI5DgvfpgL1WNlvzXdbAT6Dm1
         2jaFGdX9+Apl+edqYW6libE5TpR7BorTN0TgCrHx3dCu/rLy1hLjhGe+EjTT76C2hbPG
         6OqS0cnepqXsKWOF8A/730ZYRuU51OGBhMkcqEFZKutitheyuSk1DxIDsoYSOofi6c0h
         09g6PNOkmG2M1eireJXWc1eDtwn3h6kadx7mo9SfI+Y2FviJCQqyW5fBa3Ytl4jwUOzI
         r4tNl2RktqNc/Jc86qGo5gxrd62XhXuUTQJXZRihGfyffMsB7JMe/rFQjLYfMH/yq5WZ
         LjLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=K5s39SkNZJFiet5sTUAr4M1YTBqjZvggagVtt+ZeG6E=;
        b=FCffBzsDVy1Dqi7AM38T61LiiNcY+bNCk7uIDtwPoW0rC+YVNQs2uue5pHcOmSNVUt
         8lUEknEzL7pqqOoubHd1l12cZtvcLAw67nEC7tBtYeeC+lQi6jfQ/8Yb4fzl94ovGRpn
         CIUWTO55CcmUbKq3g2K6CBSSqHdTQ6WZfZqMkvvGlcVoCeTduQdAISuGV3+SExm6cmon
         iEzs3v+nMwZD2vp/HQd5TRuH+gG8DzCaOX0jZN1JNdD6ImWX8q+EuUbgxfALHWVL+LsW
         glqTS693DZ1HVfiC3ItDn0GQ3DUa0/3fj3fWv3yqttcyxEZo68RsJcSr4jgwT8RfMBbF
         5waA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="sK8w4/7+";
       spf=pass (google.com: domain of 3lx7_xwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3Lx7_XwoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=K5s39SkNZJFiet5sTUAr4M1YTBqjZvggagVtt+ZeG6E=;
        b=kJL7ubXxF9zS/IsWhpCaEPENZiQvGswpI2GN5BQTjxgZuX+3EVsSYbWyq+9FRl4Jyy
         eZiiykUhZY3EjKKYRi9mJdJzJse91vmlJO06NIi/k66tYZqoz2fXD+I0J5wasuSxzMJ0
         XsEMgRPnyeXFEjHGVqVjzEZHv+nGAxAhDAotqZpkDWVWt9GfFMGzxkYJzIyxU597t6SF
         NF+7r8kAWSTtifpv4c0DALNSlWu1T/kzUPNOXo0Oks3Al6bpgZvPGPluRAOkw+7DC/Y2
         5CBRexa3xkFVyoERW80pUA7ipstHxbCIYjO9Oh3EfP4mi6Igd7QKSzrrUJawuhhQ2LzW
         t2LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K5s39SkNZJFiet5sTUAr4M1YTBqjZvggagVtt+ZeG6E=;
        b=khTkIJKhtVoev+UOYRT6/HyNt8Xsum0pFAv0k6/oXCjsC/U4Oga/EGE8MWQkAnMM8w
         hZnJyP9JlL8lgzOd6f1krWE9iTLanW73ux2yO94e0yVe+ENj2lQmFro/+b9+VHAiUP6W
         bDiK4KAXIihd5B6hqRqDAP+kEryd5vFhbVq1X/LZZmwGhDxK6JhoDOYoS/u1KiC/c3aR
         GKoEcLu9gxr7hOSaT/QCy0fbt1k9VmX5zxAwHPqjDPZOyQUnj7CJd35swPLG236DWP1/
         97yUtvn/9iOnFIMKRW1d5ykbFpxTnfN6f533G6mpfEi9wWGquklvAd2Rv6jTCEdwxh5g
         JX+Q==
X-Gm-Message-State: AOAM530Z9vP7t67x+NWJ7sefw9I52eD0Xv5moUBy65RRFeToi5X+NuXb
	eXzdnsk/AnfrPt2rwgWTWTk=
X-Google-Smtp-Source: ABdhPJwdT4ylyfTij3d01jrX12q54OIVaNPlXf3sm659tktxkIDCEJ0amg39gi84bcn0cVjSricyuw==
X-Received: by 2002:ac8:6b14:: with SMTP id w20mr3016042qts.320.1610554928216;
        Wed, 13 Jan 2021 08:22:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:5603:: with SMTP id k3ls1342192qkb.2.gmail; Wed, 13 Jan
 2021 08:22:07 -0800 (PST)
X-Received: by 2002:a37:63c7:: with SMTP id x190mr2805121qkb.277.1610554927739;
        Wed, 13 Jan 2021 08:22:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554927; cv=none;
        d=google.com; s=arc-20160816;
        b=hZIKqEWZXhkasC4cQAghczpOBSQOezeHULHXn3UqqM83sMcpKFEXw6V39wneZvro18
         cR0KUjZTIHLJWS6/5quGdflFjot1TCyp4l0psx3n1ciXfsYKkRZqaBbT1PC9Tbv/m2rk
         zZ9CF16Vn6Bf6xU4S2eGnj3YF2H79GjIU1pD4+0ZapUNVqBLai84Q+DVyGcRE/w7URdf
         31+UqgKjV0gY8Jweks47aeJZjFO+uYQBqPZNbfWO/tzWy4r8R04/EBSxOtPNqm244sAS
         dml2jeuzexFOF73MEUO0QhqGl0r+T6lJW9Y+VbuVZ2hCgUkkcBPUfoONFK8sbnputGK8
         DBWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=AYU8RiBMDoH8LqbcE5Bsl4HVhMUvTlIJH5ygAkCw1uo=;
        b=yGyq5c3bM6Xd6iey3yHXeO56Dqo4mSFJLmMQyAVYu1pI3uOuSUT4DMpiPjeuEIIxdf
         X5cFq5DkfePGy1Z51rCDxNT/GBilcbdk5VUuyk3Wui6zn7GUL/y3CJDKIQ5hvsA/ZAHU
         x8RSo5qvx3CM2aIe2fOYQayCVj393g9wFsT+QClwL0VPVZZ2s5wH/mdoNn7knF9PD0ec
         Zzgyd8usCEad6npYvuUNlJAHBsUFVyzFiL+PFGTQupKfHHiEsCnYzsMxYgOp7cNvHe6B
         /69Ecs6SzefVJrng+UfuXkwaVzuKIypsLyzEl60jsTYmdokr0p0BrHcpazXLxaqqT0Ux
         gufQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="sK8w4/7+";
       spf=pass (google.com: domain of 3lx7_xwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3Lx7_XwoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id p55si219156qtc.2.2021.01.13.08.22.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:22:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lx7_xwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id l138so1720693qke.4
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:22:07 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:fe91:: with SMTP id
 d17mr3133660qvs.50.1610554927401; Wed, 13 Jan 2021 08:22:07 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:36 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <1b884616c85091d6d173f7c1a8647d25424f1e7e.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 09/14] kasan: adapt kmalloc_uaf2 test to HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="sK8w4/7+";       spf=pass
 (google.com: domain of 3lx7_xwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3Lx7_XwoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

In the kmalloc_uaf2() test, the pointers to the two allocated memory
blocks might happen to be the same, and the test will fail. With the
software tag-based mode, the probability of the that is 1/254, so it's
hard to observe the failure. For the hardware tag-based mode though,
the probablity is 1/14, which is quite noticable.

Allow up to 16 attempts at generating different tags for the tag-based
modes.

Link: https://linux-review.googlesource.com/id/Ibfa458ef2804ff465d8eb07434a300bf36388d55
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 283feda9882a..a1a35d75ee1e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -382,7 +382,9 @@ static void kmalloc_uaf2(struct kunit *test)
 {
 	char *ptr1, *ptr2;
 	size_t size = 43;
+	int counter = 0;
 
+again:
 	ptr1 = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
@@ -391,6 +393,15 @@ static void kmalloc_uaf2(struct kunit *test)
 	ptr2 = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	/*
+	 * For tag-based KASAN ptr1 and ptr2 tags might happen to be the same.
+	 * Allow up to 16 attempts at generating different tags.
+	 */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) && ptr1 == ptr2 && counter++ < 16) {
+		kfree(ptr2);
+		goto again;
+	}
+
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1b884616c85091d6d173f7c1a8647d25424f1e7e.1610554432.git.andreyknvl%40google.com.
