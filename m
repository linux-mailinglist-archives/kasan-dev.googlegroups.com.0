Return-Path: <kasan-dev+bncBAABBQGORGIAMGQEVRNLKRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0067A4AD873
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 13:51:14 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id n20-20020a6bed14000000b0060faa0aefd3sf11248612iog.20
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 04:51:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644324672; cv=pass;
        d=google.com; s=arc-20160816;
        b=TJRXuVkkLJuXeWuEvlsOViyKes7VUAhO62Zk3qYZ2kgPIwIQ4Y5WZSbVkbPVxv7DAV
         7IRLIuTE0s9naBunxFn5rgWGjp74UEZbQ+ptPn0gx9EqgaPPTrmCb8qiyujVGtKpLhly
         r3GWXI2s0O53h2Ghc++UyUu4tHJDQAydYIYPHmHy3bdcJ8cm+pHW4+0fV609Elz+Xu9w
         asOq+W7EQt9VyBzalyrx17ytBSIjZ8vLa1r77ZybExjUgWuw/WeOGdod1HtayHJbDOA3
         YPg4ZrpC+bYiNOIXfcBPAfpddhVtM9wiFxv6hxf8cw2bib0/l19/VuJnenOKtJCICb9I
         BH6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=imESE5Io4NAimdLHlgV0WMdgyaT7p6Q66DlxgBijcKU=;
        b=KghQNjMH37SLRrmzhdz/cGm/4UxzIU/RVaim6IqqKyYs19qayeVFIeES9p5pBl3Zc4
         sEHjAz6RXIjP3cYyKNT/xIbjF1fMGGATlpKy3YxhRhSy2EivyscSyvNo5Dxav8FFvFM1
         eUttQpny7U2Aca2DxEOJRonSZcVnxk/cF/pkhw+tdzwW70AB8ozM6eO6Ua8kkQNDCp9S
         eVLqY8RHwFHxVQVRgOHPpMdBjKqipvUbhK0xCFiV9pEbEA8gnuCcJ2uFSol1VkaUkW9n
         FIxHPE873hWmn8M79aqLdAPNX3wM1pj94HEOnAWOW6XyHnODdJXsKiBimUVyiktsGfO4
         pF+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=imESE5Io4NAimdLHlgV0WMdgyaT7p6Q66DlxgBijcKU=;
        b=H5M3l1Bac71LWfQ1P+S+WkSIifZ2K1PZIcTpaaZSD1NSjAU/d8gr8IZ0ZkP7Z0LwSh
         9+2+eI2/OYS9WHNBAbwI+fWWo0fd7dE7PgzcUCUD/7E+6abwvOWpTudjgzV5hcnKXd3U
         OMSAdUWcxBfdg1aVry5c7cDfXOXZp4YuuhqCkWUrRnwQqzmNjedy1gCUcWwYhrekqpLR
         xcvhSohyIGBtGXrdKGv+sk+x8lnejIEKv84Of4djA8pRJ0iTkZnUnNX4zHmuMcA55q1Z
         +UPHfF+gOswXQe4w4Foc9IbcDJnjGOZW5xP9QMigZB3aVsYEUnLotpoww0npZ0AVwiry
         yxEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=imESE5Io4NAimdLHlgV0WMdgyaT7p6Q66DlxgBijcKU=;
        b=GwWYqSnlcnnJhAgoA7LjtcWmh025kWtreRYU6JAFEVHp75AlDHgrly7YL19BlMzrba
         qY3WsCB3YUyghq/e9XMwGURJQuUhs6zRzbVo5ik5O0/gwS1Y8ZgquoMgibysY9sFX+KE
         p+ajFSAhdUalsPrJ9FEQlRdbo9rGpTxWLsCA6BK1238QvUyEuDpmeA9K9xAVAhb680NP
         L9NzhU7FUNjW6VuZx8pKpPPy32f2r2Vigdkmrm+Cu60oX4ErBuU0M2G4ssjuKMfKOxiN
         VrlXgCJNh/FexLA61VEZWSiBoVcrGstUKLBFlObUS/koixlkzcZB6RZ2jbi5tRKx8NN7
         uX4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324DIjTM4f8gVTtU10dB66oIVtll8PA+p6SF4cHVB3qjWdoK03b
	4bt0LnNXIO6j4z31PlPaNnI=
X-Google-Smtp-Source: ABdhPJxq1OSGGHy7ipCcKY518jFoHU1qExSeG1Qifc258aq2dl7gfHtBTbgWVeS5kKQnJaC6zoVMMQ==
X-Received: by 2002:a92:cda2:: with SMTP id g2mr1899326ild.29.1644324672804;
        Tue, 08 Feb 2022 04:51:12 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1ec:: with SMTP id t12ls131937jaq.10.gmail; Tue, 08
 Feb 2022 04:51:12 -0800 (PST)
X-Received: by 2002:a05:6638:a8d:: with SMTP id 13mr2150023jas.104.1644324672452;
        Tue, 08 Feb 2022 04:51:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644324672; cv=none;
        d=google.com; s=arc-20160816;
        b=pbwFwW4Qai7kAn734yHbFaysIGo8uia00X76uUU2igSoJvBYjY2y+mQRTisscd5g49
         fUvMTKbqbLiqJ8fEvYwljVLqUKpYuzMg7YMcvVXv2J/Zzqh1wbMGJfRRfqBF/Fr6xeY1
         WHlWE+4QiKMcEtc+UUMwhILsULHmCJlc4tVxfj9mRtLaxGkr5NXP1B5Y1uGF+JUIaBb2
         7TwSgwzjrbTGdy7BXa92XdByZfvgUaep7LQnvgUnW/ZnpDvw1SxB0tmyuGCwsCWZVbwM
         L2UBxJd2unLEMh0Ci2iJHh46auyOtcT/9gExUoiDMQxqnDFusI6yXlggJu/UqC5mf35e
         pBtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=2Q8GGwxOP3YVve+830JMFK+d5ayFOGiGaSg5RbYCCpw=;
        b=FVI/DLs9ASvJEOPzvPBAZ0n+axapOYkeWmH9JdIE9xpVd3/W3U2rCJY65T8Hpulfvk
         BFWuzJHdHkiknBMj2LCJiBidcWtmoIij6yq7J1rZsh/2kug9bL8kjq8QrTUFpFXwXgSu
         Ln3+fO9o8fji+qrIZcQyuryvtZNXX1VO40NJddUlSOZHXr/+ObPWRagA+2GvXgl6W4CD
         hQXhmlMwDHRfVCy5tKl8kNu46nUXv0GBJwuq8WLvRfHTZu2mvdpUnX24ncC5qjANHHlB
         iHUxXOLueT58B6tj3mifCO2y1FfgWpncMfXpLJi4S4ivrPKxZ+olVInuVK/w94CFOmxN
         eb8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d15si1431690jak.1.2022.02.08.04.51.11
        for <kasan-dev@googlegroups.com>;
        Tue, 08 Feb 2022 04:51:12 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9DxL+M6ZwJik0oIAA--.26524S6;
	Tue, 08 Feb 2022 20:51:09 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Xuefeng Li <lixuefeng@loongson.cn>,
	kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 4/5] ubsan: no need to unset panic_on_warn in ubsan_epilogue()
Date: Tue,  8 Feb 2022 20:51:05 +0800
Message-Id: <1644324666-15947-5-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
In-Reply-To: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
References: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
X-CM-TRANSID: AQAAf9DxL+M6ZwJik0oIAA--.26524S6
X-Coremail-Antispam: 1UD129KBjvdXoWrZF18uF1rKFWfAr48Zw47Jwb_yoWfJrX_CF
	yvgFs7KrWktr15uw4rKwsrZr9ru3429a109F4xWwsFk3y8ta40gF4kZr4kZFyYgw45AF9x
	Aws8XFySyr4rCjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUbyAFF20E14v26rWj6s0DM7CY07I20VC2zVCF04k26cxKx2IYs7xG
	6rWj6s0DM7CIcVAFz4kK6r1j6r18M28IrcIa0xkI8VA2jI8067AKxVWUAVCq3wA2048vs2
	IY020Ec7CjxVAFwI0_Xr0E3s1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28E
	F7xvwVC0I7IYx2IY67AKxVW7JVWDJwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVWxJVW8Jr
	1l84ACjcxK6I8E87Iv67AKxVW0oVCq3wA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_GcCE3s1l
	e2I262IYc4CY6c8Ij28IcVAaY2xG8wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI
	8IcVAFwI0_JrI_JrylYx0Ex4A2jsIE14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJVW8JwAC
	jcxG0xvY0x0EwIxGrwACjI8F5VA0II8E6IAqYI8I648v4I1lFIxGxcIEc7CjxVA2Y2ka0x
	kIwI1lc2xSY4AK67AK6ryUMxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4U
	MI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67
	AKxVWUtVW8ZwCIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0
	cI8IcVCY1x0267AKxVWxJVW8Jr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4
	A2jsIE14v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU
	0xZFpf9x0JUSjgxUUUUU=
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

panic_on_warn is unset inside panic(), so no need to unset it
before calling panic() in ubsan_epilogue().

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
---
 lib/ubsan.c | 10 +---------
 1 file changed, 1 insertion(+), 9 deletions(-)

diff --git a/lib/ubsan.c b/lib/ubsan.c
index bdc380f..36bd75e 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -154,16 +154,8 @@ static void ubsan_epilogue(void)
 
 	current->in_ubsan--;
 
-	if (panic_on_warn) {
-		/*
-		 * This thread may hit another WARN() in the panic path.
-		 * Resetting this prevents additional WARN() from panicking the
-		 * system on this thread.  Other threads are blocked by the
-		 * panic_mutex in panic().
-		 */
-		panic_on_warn = 0;
+	if (panic_on_warn)
 		panic("panic_on_warn set ...\n");
-	}
 }
 
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1644324666-15947-5-git-send-email-yangtiezhu%40loongson.cn.
