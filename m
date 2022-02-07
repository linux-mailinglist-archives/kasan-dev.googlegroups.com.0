Return-Path: <kasan-dev+bncBDHK3V5WYIERBFEWQ2IAMGQEI7MVBMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AE344ACAF3
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 22:11:49 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id y19-20020a2e9793000000b0023f158d6cc0sf5013675lji.10
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 13:11:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644268309; cv=pass;
        d=google.com; s=arc-20160816;
        b=ymUGnWVfitcbSj3QY6K8xP7qy2v6Uu+fg09Iunx52gC8mkfx5/vQGCXzeiM3aufb0R
         d/cueLt7c55ZjMBrVWw2mQGQqDx3IrwFSNw035Hz0X9/HSQlMz0GA2QTrQf4c2peyp1m
         499J8F+kzHo8y51vR+wzhFVyL81ES81pK/SLCJu5hiH8pLIABSn8ypnqBaYY2vdXrqVT
         nI4kjmO9wXYukLqWsVCMqDwbANeayTi8rqxmIeDTpqCOVFTZeHP0DM43LHO4uphPHoKJ
         +u7W3FGlslVPSjHElOhOWxqO+sX9JdMquBFfNUS1ZAGHRpLtRn+o3phJj4tplHq6hubh
         Kl/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=91LSib+kINjchGFtvYzY1DA/oSnzJw4jhDPJloh3LBk=;
        b=ri/IwJzUAKOT8h8B3w7lJxt1lEhKs+RO+KYvxwZTF9b9BUofg4hTQt0SGWrrt8zQcw
         q+c8EuPXJaGPesi699tyA90seDzh3rTXSZozd/WJTq4tdXvHAuS7lq0p66GqktWDPcxs
         A79OY3qZnX20BswM/M8zHr7ruxNptZmafkzHU1AGnnmJgAiooseND6RnmQWpcsFG+DTG
         Ga0gq89pZWeM9WK/ymiaWOeM7z8w0f8S5vpn0rddBjz2Vkv4H3/hLNVec+sy/LbVn/4W
         +Vy+Clg0f6KI4rCRInfmj8Z/otQSiBHQDqt8mZIJzY9WX8QVhQ3ZGV5AW+LKOJX+fcVN
         w2Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=U0xYQyzv;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=91LSib+kINjchGFtvYzY1DA/oSnzJw4jhDPJloh3LBk=;
        b=nXsHS0Shy8Thew5IIF4siNdZVHjjKxgtnCnjh4mLUvSNXgXSDEs8nJI/58E2v0za1q
         B26veFO+qYEjBb8O8IacpxSEvMLTomSfIPkM61k3EAz/UxdnxXz1Hlwea3qO3O84Qzx9
         yXwT2qATpy/dwiizOkfAMGAzvoA2fNLrtfwIDzmUxD39gegQustm/o5z3NIcpfYm7V6F
         ebetiFcGmiqbX/H3YsDM8kINDfAChs7rxm/ZDMfWkd8sohpORj6MKCY7tUMXr4u+E+TN
         RJkY5Qrc3V9R9Hi+TCtL4kZNuncZu6tpFZ9rUZU4/xDT65PDcAeytK8p8eK+7h+MKkD4
         nknQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=91LSib+kINjchGFtvYzY1DA/oSnzJw4jhDPJloh3LBk=;
        b=yvttoD7W+osSnSJ9FzMk50iylkhwjxsB29FNKgrbXFIKIC+SNwMebYxVtI5uqONBNr
         YhXnHWdZrZn+9vvswSs91cBMeYR3+OSjbWptduOTNlsP1ZWufqpGuIBB9doWinI10J/I
         zDz/HxoWoVG9Z4eoY4G/mD5FRujYMgRt7PJg1c6G65hST3VI42a5ZauQAO0HIO5J5T8g
         GRh12UVFqJ7ZKXhx1BOpr8Ti6c9g2fJdxbqmRtOGYskO02Di3YCtTsvccmp2F6WROJhd
         MdE0icXE7xkm7kYX1ze2c/Hd3ZZaujZ2QRNdg/MGPPEvV4QljmiEmYSURZHss4nNQJX+
         q6ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cYnJg7PZ0e/R9kfJt6HSEhpB96mQv5FBXQnqbgXHPW12pgsZd
	KRM0q/lb2U2Ax/GZqfwV+10=
X-Google-Smtp-Source: ABdhPJxgdwN/W17YAbp8o3TUZJ5ch3tgFMcF4QxN65anS5vPDhpumkVh8dl4U6lgTZn9/+DBPAYh6w==
X-Received: by 2002:a2e:a4a9:: with SMTP id g9mr845997ljm.289.1644268308881;
        Mon, 07 Feb 2022 13:11:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a26:: with SMTP id by38ls1602275ljb.5.gmail; Mon,
 07 Feb 2022 13:11:48 -0800 (PST)
X-Received: by 2002:a05:651c:1503:: with SMTP id e3mr866435ljf.456.1644268307939;
        Mon, 07 Feb 2022 13:11:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644268307; cv=none;
        d=google.com; s=arc-20160816;
        b=E+zwIgD2UlhGgc853svwX1/CGg8tncOueHgVKZlRrs1h+3PrtrRuIDNq/RBos63U+L
         N/HZrV3D0WwxV79wdWYrl2Ng65st6l+P3eoT+RprVcIx8rLBaecL/+t3ox8u3Q+joJw+
         i0YXwNgKzGd5bEqnl4jL04L49nJnSfCOQ3yEeDIPVSzho1FFPLRt7MA5ZILDw7KwW67z
         v3ZDoEU6L9+UcMktuMjCRmhlMImqGo9UkLj6azLu2aLmUvf9WE2E+4pxkJ+4gEPoKkqq
         pH6i+t8LfMvlrNhQgENXuAbxsAfEZvPFPY0SYrEUUaeOF1cSMVOSIq9J8e0VJlsM610z
         JfVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Y0o7uOOFR/F8wdFMHcK21ektAthAmrg4gw7mo/oxzd4=;
        b=zemjvIjupRXIoRz1JruJFhQ6trBdWxtm13LsnHFamxc9gArC3hnR1R2pBi593ZpwlG
         PwdSR93qf95iVtSOzzODB5eCv6GDu8pfwE8307V2U8/4fU2+J5haQDH+NjbwBZFKLyT0
         s2B9TXG/XCufaIKb2tJwiugbllfwddLkNFdytQH7Qtg9XENdmCchumgM9zw8j/CpLVve
         J8ORWzm/jK7c6kVL1RX2bj6Tz1JxHQ4iZVHndEH282kabJkDfAa4mQsnjurE69csZzHA
         34TWltJL4Au7shPG+s9N/a8rp5UhcKB3jFq+GPe2QXhcECKqQ1K3piV0NtFvR//PVuAn
         lLQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=U0xYQyzv;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x636.google.com (mail-ej1-x636.google.com. [2a00:1450:4864:20::636])
        by gmr-mx.google.com with ESMTPS id b26si542512ljk.1.2022.02.07.13.11.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 13:11:47 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::636 as permitted sender) client-ip=2a00:1450:4864:20::636;
Received: by mail-ej1-x636.google.com with SMTP id m4so45983625ejb.9
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 13:11:47 -0800 (PST)
X-Received: by 2002:a17:907:d28:: with SMTP id gn40mr1252294ejc.750.1644268307679;
        Mon, 07 Feb 2022 13:11:47 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id z4sm4047239ejd.39.2022.02.07.13.11.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 13:11:47 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v3 2/6] kunit: use NULL macros
Date: Mon,  7 Feb 2022 22:11:40 +0100
Message-Id: <20220207211144.1948690-2-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207211144.1948690-1-ribalda@chromium.org>
References: <20220207211144.1948690-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=U0xYQyzv;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::636
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Replace the NULL checks with the more specific and idiomatic NULL macros.

Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 lib/kunit/kunit-example-test.c | 2 ++
 lib/kunit/kunit-test.c         | 2 +-
 2 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index 4bbf37c04eba..91b1df7f59ed 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -91,6 +91,8 @@ static void example_all_expect_macros_test(struct kunit *test)
 	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, test);
 	KUNIT_EXPECT_PTR_EQ(test, NULL, NULL);
 	KUNIT_EXPECT_PTR_NE(test, test, NULL);
+	KUNIT_EXPECT_NULL(test, NULL);
+	KUNIT_EXPECT_NOT_NULL(test, test);
 
 	/* String assertions */
 	KUNIT_EXPECT_STREQ(test, "hi", "hi");
diff --git a/lib/kunit/kunit-test.c b/lib/kunit/kunit-test.c
index 555601d17f79..8e2fe083a549 100644
--- a/lib/kunit/kunit-test.c
+++ b/lib/kunit/kunit-test.c
@@ -435,7 +435,7 @@ static void kunit_log_test(struct kunit *test)
 	KUNIT_EXPECT_NOT_ERR_OR_NULL(test,
 				     strstr(suite.log, "along with this."));
 #else
-	KUNIT_EXPECT_PTR_EQ(test, test->log, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, test->log);
 #endif
 }
 
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207211144.1948690-2-ribalda%40chromium.org.
