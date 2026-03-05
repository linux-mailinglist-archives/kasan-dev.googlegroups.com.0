Return-Path: <kasan-dev+bncBCSL7B6LWYHBBLFEU7GQMGQEGVB2QGY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id kHXfCy7SqWmYFgEAu9opvQ
	(envelope-from <kasan-dev+bncBCSL7B6LWYHBBLFEU7GQMGQEGVB2QGY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 19:57:50 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C57762172C9
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 19:57:49 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-5a1349fd6dcsf562710e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 10:57:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772737069; cv=pass;
        d=google.com; s=arc-20240605;
        b=DKHgXKRUweIm0zw3hoIszWZLdWygn7DLkA8vRxGbyRSpw3zKMhlxI9XPXlr0mo/1J9
         BL36+FZkWCQMRnT1i3/Crk+z6e+KPdE/PWS+ElCHKlZq5Ulc+AjTEcoW1PKXzcOY8eNG
         FddLEzZP0diEnIib0ZM6CS6LWGQqcZsO3sDfRzlUE9kEPLiEBqAtpkwLCGAN6vmK130O
         /+p4BbVEtvErmyWNjoNwlE16FrZSMgXzJOqKXRm5PTVqhd9USAhorDUoqgQWUah8Jytk
         Yq7fQOCfrVoY5vAhL8ihLSon5bWnoYPRlA+5H3KMovcBRLMBjKBzJ+k9eYXjan54Zgte
         xMPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=+u253DWXveuTZlJlzPXaRt6pXlbue16n3QAyJ+bnsVk=;
        fh=q2+bliO+IdP2n2NVw2J7z6a6I5uYvFXukavTHks9MJs=;
        b=OkwOpuVMWHIQwbTPQw61B59uEgkyXMlqtRGycPsx1qUeAv3Ygd2LY/86BIW6dt3kCJ
         2Sw3zniQUzU1em2EfTa0rSBxR0JfBxbLnP9iSAYQAiHzWnvmyxgOliITLdnTYBSy2gKR
         6oBHX6L9OlrkXrpBvggRykzHkE5KgTkTpQq4EJdIg2IU6cQFAbvLPnhijpWUNhumUIX4
         t5nuJdjQh9I6JL/t65mrjlkAH2hLUsDonPBRy8/20yZH58mZoQtH4S2ttSMiWpsem7b8
         F43WN8G7sZRMhUe/quRw5EkhNMNSZTwSLe+2/kXYKMiXKNOnfqGVvUcZjEB8DeT2S5L3
         nVYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lvHmAfa2;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772737069; x=1773341869; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+u253DWXveuTZlJlzPXaRt6pXlbue16n3QAyJ+bnsVk=;
        b=JGxaulE0MSkc+uQ5vfZQ6XMt+JEW2AmQsJOhcPnRYUqwmrWUCvVE9PIlegaGWF0PTb
         vlveb9p2HxPV3vWjUMBFsXN/1kcS0zRsWOMRe2W3czutQAMPxv22Rh8yxKS+41FpxIJw
         5nS/NKeLyKaIEH326pgnPkPm1ImAtRys8juFuMHs8GdUsrfcPxGXV9Yagx0LERuwDN8X
         4b0wrykfz37D/oe/Lm8m8J5e8aH7S8sYjNgtDhmQ2D8LDiTUniCeBgMZzbT8m+PRdixf
         1EHK4cZ+WQE5El+yacTMGoT/zzl9H4XYyHE7YgggH+okFPwZmBSLWOgvZF/uiek8eajV
         9VHw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1772737069; x=1773341869; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+u253DWXveuTZlJlzPXaRt6pXlbue16n3QAyJ+bnsVk=;
        b=WX6CGJBt6ZeIxr8kc8m9WkAKva7dchRX/bIxDEjhM/BYTo7OuklgXlhTZ9RHnDw/Ye
         tuMYPM0JZylgpYmPHh6gukNUUuQUSPGKyXrO1+9b2Lx8z3ssb3OsUM4rxqFQ+RBMe0Jd
         4l4cdAgFKRPLm3/xz/H9kbjGtTPBaCL+ZgXTollRSvNHw2qTXfkNhfRdoLluFiZAyUfA
         i8jom9BmnIuDkm7IvUI/9T289ypOeWWaQ+AR+u6plHBGeBlQYdzYJWI/Mgjq+qp3eKQP
         FWWYKIZcTIJKuinmMCgzwxaVmxtrO/syMPdiHdOPbBAKGwhkLH5TWgmtdzzT97+HEGKK
         E65g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772737069; x=1773341869;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+u253DWXveuTZlJlzPXaRt6pXlbue16n3QAyJ+bnsVk=;
        b=nCG2WkpbHJ1K5ide4eZUtZhIjOeUn6DqvkGBeHJ2LMmn3g9kZ0Q9d9iKu5n9+j7dfC
         qYE4GBPmKPQS7C5kxtR12huLP13IPXlB+jljhpo0fm9FgQscZNKCAod6ajuSNfSNU3YO
         rsS4d3xmlNxtWRBe0rsurbpfR7fPtT2QLQcOxgfygrVWyjgjZs2SntPL8VNqiKBs6MQu
         +5x4Ix83Ts6t5YeFrdgZZ3OCEStfEjEoWtbsce2tVbOaapNXcFxODadaXCSdT9vpJGG1
         /4u7uN1O986zPVS739oWOpWJKFvJ7aY4I63fu7I4Geq77f0/COoWkTJywUZ6njNthcAj
         tRfQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWoa4ovh3aIfGab2DH86OrZQR0mTMMj6ydASEBar7oF2o2jLK3rbcVd+/AkLTpROxeD3sggig==@lfdr.de
X-Gm-Message-State: AOJu0YzOvxLnCkFMxrTzQjpzrtZLRDXHWQ1iUlMA9jt5k9WGNjiQyjZ3
	HiBNMplLcibOY/5hc3y6J7O36RphF1HJgfx5fEkFDkP3gJqUV9LuUfcA
X-Received: by 2002:a05:6512:639b:10b0:5a1:2a29:561c with SMTP id 2adb3069b0e04-5a12c2be6ffmr915768e87.48.1772737068798;
        Thu, 05 Mar 2026 10:57:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EYx7wKdiKuWJCC5E7kL8pfUiUZ2u86+/zJhHgC6VmxaA=="
Received: by 2002:a2e:320a:0:b0:385:ba7e:10fb with SMTP id 38308e7fff4ca-38a3393d652ls2066511fa.2.-pod-prod-02-eu;
 Thu, 05 Mar 2026 10:57:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV4U/r5sB7V+m2PeDWnE5t4/jD7Lhcr2yyTZe8c76EGA43jvGirkusxC1FQ9qz1Pr4bbqdzhCcux84=@googlegroups.com
X-Received: by 2002:a2e:9b09:0:b0:389:fb7f:3def with SMTP id 38308e7fff4ca-38a2c5b6c36mr27830851fa.23.1772737065770;
        Thu, 05 Mar 2026 10:57:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772737065; cv=none;
        d=google.com; s=arc-20240605;
        b=YECLJ460bUJerAjQbib620fNi2wwen7CNbn6azFIBCNVBk+JDCaJkzyhrX2edCCpC5
         aVJtLnCA5OA1SBBY6WQoG00FOlK64+pptyYmWBijRJgfDVigdChP1cD2VUsJ/pJVytUm
         XOPRFNGDZhZh21oJd0fRMxrPKcbWkyQBDKp6Q3UOec3/zk5AjRMmRTOtT5qxaMZEXZga
         VkxARvS/nJtaRoNySjjtTmjhbqS3pekQdyhGEWwKbwmlV7JK65kAdflvUPblaT72kqiK
         y1Xc2Mwtn46GMWWh0/oA0ipUqY38qCaT4QGn2owU6LocJm6R6AVF8OKEou225N0DcHUn
         fjPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=M96FxMHGqXkOLvQsr+HkAU1hM7UNd5HvAR5XRWMmWUI=;
        fh=yvNXRawoyblXOeZcTSIQLh9W2Nvwc/mIdY0RK6sN0Gg=;
        b=Nnl0v+c2T21NrfWa/DK628jQDbOsWNk0Pmb5m0SPWs54A5b+aMoQ4Bp6sfrogmBmpS
         7IFaJ/BGO6lELp/wJH7uNST2djF2MUh2MHyXa6xW2cCsFZ0SGXo9balhm8Hq1+QhYmrQ
         UnyK5EavOgh69pg23UbG7wn+6wbUqxAJoVthG8sSYp/rp4NK581y26R3H1HnGt601tsd
         dXp1yU5aTeXyFTzHGkQ7iBjjVsPFAijm7ZW/+9odirz0nbAFVgOVmyukxqgSnsnOqllz
         l/jrrgmNvttdxv1sSsdbjfCm6NERm+BM4CZWiiudRWE4sDShhwVbsmxqG06c7ANkxy+d
         QOew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lvHmAfa2;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-389f2f9e2a4si4407721fa.6.2026.03.05.10.57.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2026 10:57:45 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id 2adb3069b0e04-5a12c2c5b10so183647e87.2
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2026 10:57:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVq0lay/H+uOYyfUeOxk2fLUvH+Ke41+hSDwvoyzc5nIbAok1CW0OjEnAEmuXR705cIQqTbq3wt+tY=@googlegroups.com
X-Gm-Gg: ATEYQzxlm1ajZZLVIHxUu6oMLGkxpd2U23VtOQai1EWwkgNloB7X8MQ2BvGFiT8GIjs
	ltUeVpluf4W5u7+xO9poNMqlvM2mkLh4gDj1FjtaEzJMC08lcjJib933TQinWaMYtzLXt69Ezp1
	1UadIi3s3FuwFJ1o7FiSo69rLZzNJXTPMc4JgWpaXarEo1KKe0CFhPzla3hVYb0oA46HYi6n0F9
	uHq8KXkOe8+mDhk9kukuta2ZqiU/8NllKSvMjg1SLorMqNaOjxYP0OJPFmAvo9u98W+UgoLyP9V
	Ek6QlZrMAFTVrp1bD2r0rfZS0QkHGoJwuGJBqEmjQzuDvN2gON1fpg65mUBe6vPqRMJKdLUj4Xx
	NsDbGoaZjS1cXe/HUqbwpm0Fc63p+B7ivTsqdUpTo1+HslTiBMUyvL4Ten3iiToyljix3UBoiDR
	OPZooZXCx+SBMMxNACo8iHnvg4MuvthglPSVDE5LgUqY0LPA==
X-Received: by 2002:a05:6512:2c0f:b0:5a1:23fe:b047 with SMTP id 2adb3069b0e04-5a12c23cd79mr598071e87.0.1772737065001;
        Thu, 05 Mar 2026 10:57:45 -0800 (PST)
Received: from dellarbn.yandex.net ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5a12358ef25sm2163251e87.3.2026.03.05.10.57.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 10:57:43 -0800 (PST)
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Subject: [PATCH] kasan: fix bug type classification for SW_TAGS mode
Date: Thu,  5 Mar 2026 19:56:59 +0100
Message-ID: <20260305185659.20807-1-ryabinin.a.a@gmail.com>
X-Mailer: git-send-email 2.52.0
MIME-Version: 1.0
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lvHmAfa2;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Queue-Id: C57762172C9
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[intel.com,google.com,gmail.com,arm.com,googlegroups.com,vger.kernel.org,kvack.org];
	TAGGED_FROM(0.00)[bncBCSL7B6LWYHBBLFEU7GQMGQEGVB2QGY];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FREEMAIL_FROM(0.00)[gmail.com];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[ryabininaa@gmail.com,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-lf1-x13c.google.com:rdns,mail-lf1-x13c.google.com:helo]
X-Rspamd-Action: no action

kasan_non_canonical_hook() derives orig_addr from kasan_shadow_to_mem(),
but the pointer tag may remain in the top byte. In SW_TAGS mode this
tagged address is compared against PAGE_SIZE and TASK_SIZE, which leads
to incorrect bug classification.

As a result, NULL pointer dereferences may be reported as
"wild-memory-access".

Strip the tag before performing these range checks and use the untagged
value when reporting addresses in these ranges.

Before:
  [ ] Unable to handle kernel paging request at virtual address ffef800000000000
  [ ] KASAN: maybe wild-memory-access in range [0xff00000000000000-0xff0000000000000f]

After:
  [ ] Unable to handle kernel paging request at virtual address ffef800000000000
  [ ] KASAN: null-ptr-deref in range [0x0000000000000000-0x000000000000000f]

Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
 mm/kasan/report.c | 13 +++++++++----
 1 file changed, 9 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 27efb78eb32d..e804b1e1f886 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -638,7 +638,7 @@ void kasan_report_async(void)
  */
 void kasan_non_canonical_hook(unsigned long addr)
 {
-	unsigned long orig_addr;
+	unsigned long orig_addr, user_orig_addr;
 	const char *bug_type;
 
 	/*
@@ -650,6 +650,9 @@ void kasan_non_canonical_hook(unsigned long addr)
 
 	orig_addr = (unsigned long)kasan_shadow_to_mem((void *)addr);
 
+	/* Strip pointer tag before comparing against userspace ranges */
+	user_orig_addr = (unsigned long)set_tag((void *)orig_addr, 0);
+
 	/*
 	 * For faults near the shadow address for NULL, we can be fairly certain
 	 * that this is a KASAN shadow memory access.
@@ -661,11 +664,13 @@ void kasan_non_canonical_hook(unsigned long addr)
 	 * address, but make it clear that this is not necessarily what's
 	 * actually going on.
 	 */
-	if (orig_addr < PAGE_SIZE)
+	if (user_orig_addr < PAGE_SIZE) {
 		bug_type = "null-ptr-deref";
-	else if (orig_addr < TASK_SIZE)
+		orig_addr = user_orig_addr;
+	} else if (user_orig_addr < TASK_SIZE) {
 		bug_type = "probably user-memory-access";
-	else if (addr_in_shadow((void *)addr))
+		orig_addr = user_orig_addr;
+	} else if (addr_in_shadow((void *)addr))
 		bug_type = "probably wild-memory-access";
 	else
 		bug_type = "maybe wild-memory-access";
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260305185659.20807-1-ryabinin.a.a%40gmail.com.
