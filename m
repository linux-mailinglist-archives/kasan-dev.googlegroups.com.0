Return-Path: <kasan-dev+bncBDCPL7WX3MKBBPHG7DGAMGQEUY774LY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id UMZxNj4znmlwUAQAu9opvQ
	(envelope-from <kasan-dev+bncBDCPL7WX3MKBBPHG7DGAMGQEUY774LY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:24:46 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BB6718E231
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:24:46 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-506a633ce06sf67460821cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 15:24:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771975485; cv=pass;
        d=google.com; s=arc-20240605;
        b=AzNkOub9RcD8aE/Yb9z++2QAcLA+1W+9i9QzZvcV1plyzxSiTrM3/nlFnFff7fGlij
         tmPmgPBiYxMIyIiy3/2CaJA1ozey4qDF4T3Wfpt+7W0rprXOySYjPL2EPB2xs9w7TEW5
         YfNhuEQfNBUvFstuPgXXdZWCXli457C2Lv+MDe4I2+UW62egrQCwiAosqXssmy4iMi9g
         5xWCHRwLrGEPS2OBTX3VEK2hZIWASAM3HWndFVtqEvymjOXH7WkxCEwPRH242AeqzBBP
         y/PlkTG3Jn4okcz91LyjahQbuV3NjAM6ia1vcFm4L+GlUAKjmgOq+FTa9x9tMYKC9LAC
         B8Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=9N9TgI1o0r8z+Ms+c/AUIRPdxT6kdJ8utXGw8xrKBHY=;
        fh=lN2U9DKrvgOmkJcHWdmLJ7dG8mACuqFuqxtOmhieBqI=;
        b=e3swTVDa3pL8XArhjt3b7JhCGmof7l6rf4VpNRflafofVFsEGLORZlOUSvrCoBR9If
         L9HGT1qsX8PCCpUoZenUhrfazR0kSTfT2g2VGB9KqpP/YIZUO7H0kVOCHoeTCyja4bgw
         MFi03BH0kkpavmdEMprubFBkZAINiutG7QS30xW7CCGvs0Hi9xmA5s7lJ4w5TxGGMVC8
         ElnXRUdd0slICvNxbZnxBmY0v1Jj1IYM2nwgUUsq9HrDS6j3u4O9Re7qn0gHnvoy/gph
         hG7wDdgZ2ZSNvs1auajig9iKbMQO2dG2sYtLzD/JyvryuaP60JZ6uqnh4KnuqIyTAuRD
         tllg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HzSu0BEf;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771975485; x=1772580285; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9N9TgI1o0r8z+Ms+c/AUIRPdxT6kdJ8utXGw8xrKBHY=;
        b=dXqBRIDF0nBL7NUPU0p0TuEI+afzhisB+2Mwt/icLnGE6x71WyRgm2oEYT+vPeugua
         bPqBPezgQSZaeoJ7oFza9BkNcvSagfugj6lvnxpFgk0JjfKXq9TrXMjUCo1KusPvmaAZ
         2GiPOLpcy4+ddIai+P+Q2Hlq87go7zVAOcoqJeibbNBaL+h+rE9q0AIbpliE2k9hjBNM
         3fpuIbhGZ2zbkmtACUqt2j21eeRRETUXl8zJfh1OnLocoT5h6M2Ipxg0+x1UOV5vEq5V
         Fb+0FJ6570wPBGrW0RbvnZzWqm9Sxj6iomZGIguQ2LEiRbcyRh3XC3fRI7PW/1IDoOwv
         WZxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771975485; x=1772580285;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9N9TgI1o0r8z+Ms+c/AUIRPdxT6kdJ8utXGw8xrKBHY=;
        b=vvOe4Zuc6eXKuAVSBjxj9u724odCB5TBwloEm5SlhScTahBa5ZUm3SFOCl+UI1o2cK
         Qmiw4WjF87cvFFkReGpLxWX+8u1wI4cdkr4HP6k1SgbMwGRgp9Bs9yI+g7hOU8JyEh2d
         ORwbSDe73E7QgR0gP9ALagrERYrqGZTawmT0CZP43Mjl01YD132RphLa/NwoE9OgacsG
         6em2lIXKlykrpGE4Ykohwds8Xdw5jFrqVylljwLDbxWQ7sSlizM8ePwegUJE39d0gHX8
         7KmKC7q8dLCdsJGvR+NFZUa1isbqf6xKzq9gD6VzdrcLmHD4timi4sLr1wt7SXd1QDq1
         Y0WQ==
X-Forwarded-Encrypted: i=2; AJvYcCVDNg/AnMXCWH67oojrSTb790TQ7ZPu7LVTDfhafipkN6BJLy5u6GOPj/XNIYAzDzLyzp+TZQ==@lfdr.de
X-Gm-Message-State: AOJu0YwHqREov7DrankoOBXu4liOYLv2p46b51aBji1z2NYj9QbrAjc3
	zRZeI5KewJp3DoQm6ob4rDP1kB24cOIFeUZmC4uR03KR6F0BK8gYwC0U
X-Received: by 2002:ac8:7d15:0:b0:4ef:be12:7b28 with SMTP id d75a77b69052e-5070bcdb881mr170220231cf.9.1771975484715;
        Tue, 24 Feb 2026 15:24:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EQxkjo2hbmi7tIWj4prwIbWNVgfcpOze4XIYQrEG5F3Q=="
Received: by 2002:ad4:5e8b:0:b0:890:5973:709e with SMTP id 6a1803df08f44-89729c2e5cels135645566d6.0.-pod-prod-02-us;
 Tue, 24 Feb 2026 15:24:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWJNSbAO1efh+tjm3NADVSnGaeLkxHHDkkbQIfXnyY59kMmbkn+iOd9LItzKuxdIsFFT1mRk9/u9Wc=@googlegroups.com
X-Received: by 2002:a05:6102:c04:b0:5db:1fbc:4462 with SMTP id ada2fe7eead31-5feb30da52bmr8183698137.31.1771975483403;
        Tue, 24 Feb 2026 15:24:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771975483; cv=none;
        d=google.com; s=arc-20240605;
        b=VWQ8uIhG/QyNWXAMYA2M5Wq3yts6dFP91aeSNP3+YA33uKaNCpQIXI/hWG60PWQS8Z
         WTzOOrdLawva65qUEj1wux0SmbIjWecOExcoRmETWHgbOkpAjYv2zT1NHyrokdXDGlJN
         IYpjIfdNBvfu6JG4/IowRnCuAo1yMrtWTNIZe5mQbpZy56yzVEGM1JSZNvwvobPYB7t4
         SBqPa+oHdx0ocp373gDMGds3RIZVohP4qWNTefn/RNIAbDaCsHZFdydAE/ZHSLcbEwRZ
         v96bBLQFi8watVlddqOESa+PzdCrWODGVDiAphkq6Np8NrdN7Mn9GDnqQ8JybsL40BHR
         tnRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=9WoKJUq0r5HOlDlpN9blO125OgrTyZU5cP1fA6ilMh0=;
        fh=VkCe6GoblGgdT+esOVAEvjC2VBqq4ZuyoJMbinIvvjg=;
        b=LlpJ3HVEm7D34xjJJteHdy1aQfsoUHueA/THn7J2seHE+DptTJ69OWEmVM4TXEukny
         lpITstiEeuqPnqwUA4K8tWFlV9cBVZ63hjc3aU4V/JDAbhVbMtCyYeUKMc2IFn/uY2k7
         8NUQfirNKOwz4N3k4CVMGqiygvkCBiVDIHgGbl9Hbc137MldY/WWEfDZwOIquKnPMbO3
         NBJX0inkMm8mbt8fG6AuFRJ7eQU/kiJPkGjEgxK5QqzF1VThzMkKEkJsv7P+pTsWaAPY
         ddZgaGd2QE6fQayZf/v+sSL6qri9+8WRNNB//6+ukk287ZTwVbQIC04pYRjMARQfajO2
         I45A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HzSu0BEf;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5feb63b95edsi315083137.2.2026.02.24.15.24.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Feb 2026 15:24:43 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 9ECD160051;
	Tue, 24 Feb 2026 23:24:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4E133C116D0;
	Tue, 24 Feb 2026 23:24:42 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <kees@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2] kcsan: test: Adjust "expect" allocation type for kmalloc_obj
Date: Tue, 24 Feb 2026 15:24:40 -0800
Message-Id: <20260224232434.it.591-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1839; i=kees@kernel.org; h=from:subject:message-id; bh=xupxSd6KKXCyn4CF6vOxdGC2/8h8XM7Ljals7v3P8Dw=; b=owGbwMvMwCVmps19z/KJym7G02pJDJnzjC3+tD/h+OAf0Lli5tPZTPkXdqcsyTH+aMXHw5Kgx eL37/zUjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgIn8c2X4p55/viF77c/ZQY+u 3DNs2rXni7XJlYr8zOe1c2WXVsjd0WVkeFu341dx9IYqtTnXBPdnrbzyIeV7R/u97zMyjXtv8Px ayA4A
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HzSu0BEf;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_FROM(0.00)[bncBDCPL7WX3MKBBPHG7DGAMGQEUY774LY];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	HAS_REPLYTO(0.00)[kees@kernel.org];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[7];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 4BB6718E231
X-Rspamd-Action: no action

The call to kmalloc_obj(observed.lines) returns "char (*)[3][512]",
a pointer to the whole 2D array. But "expect" wants to be "char (*)[512]",
the decayed pointer type, as if it were observed.lines itself (though
without the "3" bounds). This produces the following build error:

../kernel/kcsan/kcsan_test.c: In function '__report_matches':
../kernel/kcsan/kcsan_test.c:171:16: error: assignment to 'char (*)[512]' from incompatible pointer type 'char (*)[3][512]'
[-Wincompatible-pointer-types]
  171 |         expect = kmalloc_obj(observed.lines);
      |                ^

Instead of changing the "expect" type to "char (*)[3][512]" and
requiring a dereference at each use (e.g. "(expect*)[0]"), just
explicitly cast the return to the desired type.

Tested with:

$ ./tools/testing/kunit/kunit.py run \
	--kconfig_add CONFIG_DEBUG_KERNEL=y \
	--kconfig_add CONFIG_KCSAN=y \
	--kconfig_add CONFIG_KCSAN_KUNIT_TEST=y \
	--arch=x86_64 --qemu_args '-smp 2' kcsan

Reported-by: Nathan Chancellor <nathan@kernel.org>
Fixes: 69050f8d6d07 ("treewide: Replace kmalloc with kmalloc_obj for non-scalar types")
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: <kasan-dev@googlegroups.com>
---
 kernel/kcsan/kcsan_test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 79e655ea4ca1..ae758150ccb9 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
 	if (!report_available())
 		return false;
 
-	expect = kmalloc_obj(observed.lines);
+	expect = (typeof(expect))kmalloc_obj(observed.lines);
 	if (WARN_ON(!expect))
 		return false;
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260224232434.it.591-kees%40kernel.org.
