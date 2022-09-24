Return-Path: <kasan-dev+bncBAABB2OJXWMQMGQEWCZBZVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id DA9775E8F98
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 22:13:30 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id r7-20020a1c4407000000b003b3309435a9sf4225991wma.6
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 13:13:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664050410; cv=pass;
        d=google.com; s=arc-20160816;
        b=N2J0CNrYZLDkE7I2ZfHqHmx1EPG1wYeyg8y16MxxPKdxBetCXniJbUQ58hE3+Zg6hh
         L4m65VOyal+C5SS8ayTQ/JCusvuK+8HPe6EZlnb1N99ZWqDYCqAj/7nC70ftTJ7kMAEm
         u/tKWecjLnxIzgxd1ITlH8BIdHwIApqaKIYPfim8gnSfqlk8gDHlBPRMYq5o8ldPFHhs
         DtolmGkISU1SHYtP/IzM/z8Y99cXG2uxV9CoLhfVceI+LqWCrPSVxsnZooiaDND2hDis
         atJYBubg0sJaIO5R4+nHLFyjr/aSVCaBU8oEgxYg0LCsNi1XnorzFRf2H9CrNQhNCk6W
         OFXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=yuE+MTmCWD76CXe64LNPMLHHyMnhU8uwpg6lznmfjyg=;
        b=Smlc0VJmB5PlynjyFgOt3f+Az/cYj/E/HsMvhdlX97ac0lmuicTpajztN5aIMi+7Yr
         XL2JB/O2EWeLHen4eaXV1/7fDkbf5dBJxwr9rcw7GguMPz/LpikoPosChrg2HxfWolxX
         MN5RtOY3lmCG5XTcCVyF/TNNoAzsuLT3t1j/BpLXs7hGJXo4EzQZG8lVMyDrHMaS1H0U
         R3WPYFcW5Tkb1ul6TglKCUiGeOZEYjorgrFYgcVTsac5LVjHNSppajDJt4qUmzccj7a+
         /xBv+hSnywpMh7WSUTHzQqFIVqdkOmxmvk8NdXe1hGQLIj8kippmM+MyYFXQx1tDeloG
         f3xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CcFOjNnK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=yuE+MTmCWD76CXe64LNPMLHHyMnhU8uwpg6lznmfjyg=;
        b=WwpwlrKc8GV3EZxtfjJG6T9sa8tjp3FaU65F/2QSUVXurZsd6LnPn3f0vGGYHY9UTQ
         psuqCoe/slnK5ZXRiGM/IFEUM+nVMEU2CjVhAIUq8gqf9xTd81PCu1vrrcZH2YzViLTH
         mH0i4eDOBJsyDx1hlH1skOIs0ocy+nBkuu37mlYL7Gke2kaiLKpj4ciyPFuIe6EnV+lk
         MMpA2Qd+ICQaQElDw8zqfmdKm2/ccXy+v6vJU9bmLtCV6AzYlKV6xlRjKVjeeIPKSpgx
         LC6oLhjy6JLOfJr4O81FOvcHYEo+z5zfPdirD/43ck54mxh26eawA+AM5vEivp6NeuLq
         1bbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=yuE+MTmCWD76CXe64LNPMLHHyMnhU8uwpg6lznmfjyg=;
        b=kWW55Atq7IQGtScDkqqxlPAhlfwtd8aqcrXrHhqvVgJw2IIXR79rY8KpD8f2PXXtcO
         JYFz2XEJr+rUPsXO57voq6Mz8qwXMjCLOAWC/O8SZ2NJ2FD9QT+e+h8+U3NbLLSgT3Rz
         wvWdnH5vEoKa7mauPGuYok77nhrfo4r9oPTP8B3oQZmHVVBlNGsM9EvqvAesa5ClqKzA
         +DIDR0uFklMQbNlggtROIc1TRP4e7hyqhu89k4grmqZg9MUFPJom+BqU179kNTL75sVo
         mOzFshJilPcvX41LlGR71h4qJzXu42C/1IgsagqegIrgAYfmNEFCAjTj/8YIIQ4gcsnd
         AEjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf11vI0/28NluvMEfYSK8KVWqF5i6P5GMxu4X2yhR+tHhFXtWNie
	Zt1LK++huSCyxz+vE0Ad8Q4=
X-Google-Smtp-Source: AMsMyM53bcXBtvgqQ2WNhxzTL6Bfy0tWJyrViU/afs/YDeCc78bhp6Jbc/D4ZpFXbk/dmlAkVjXwPw==
X-Received: by 2002:a05:600c:4f82:b0:3b4:9f2f:430b with SMTP id n2-20020a05600c4f8200b003b49f2f430bmr16896691wmq.16.1664050410265;
        Sat, 24 Sep 2022 13:13:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f615:0:b0:3a6:6268:8eae with SMTP id w21-20020a1cf615000000b003a662688eaels6806294wmc.0.-pod-prod-gmail;
 Sat, 24 Sep 2022 13:13:29 -0700 (PDT)
X-Received: by 2002:a05:600c:2142:b0:3b4:9289:9d4e with SMTP id v2-20020a05600c214200b003b492899d4emr10066820wml.197.1664050409479;
        Sat, 24 Sep 2022 13:13:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664050409; cv=none;
        d=google.com; s=arc-20160816;
        b=CdOCQdPS+g2vkdir2W5HIux9tPAGy48gDrG838KO5JXlYlyyMcd2Gd+8LoSN0tXTvN
         3XIxMcagfTcDsrbyiExvjeOqMAOZ/RJVF8AG6oC5FCrTGyscro+RHsw/7ZE5oJO1REhy
         RvOWH7kxB/gOcpj4n10GMcHLq2VkGovVxkRnnDvBn74VpWv50Vk45sqr1pxbcROAMcyO
         STdmJyELJMc023Sdtx38d4PclKgu+oK0fF4q1OS9Os2UL1wVlal0xA6kuRTTwbozKH08
         wxDJHD/+8/NNdhVFA5Wu+xVwVpVSKRYHLT+hVtMCYy2xjtDDCvu4ZTk+ERs+ZKL0mS9w
         4wzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=EcbtpHcwl1Nm1cXUQncscydMAW3SGpJ+fUyDvKUD0nQ=;
        b=AmSAl9AICRHi9eSNgeQEAPRi3CQDfsUNkXSOfnqOxHfcSoWoQhRTD0Mkot3nIF3S5x
         tjkW29oNvAI1H1hhJpSJbTB8tXZNFsEqWHsBl1kkDk/oB5Yi3npf/ujNZL2HuIMK5TMB
         jpWxEf0b1NycoVPQ3+QEDOucteG6U8XSY/qCypHnIyejNJ+9u+yFnk3IS6SpmMNMtyf2
         AWRGHuGhstGHqF1AS7a2EPT5H20t9Y4Xz9wkTFz6c9y/pfGYV46hvf7E6uzWRk+VgtC5
         BfO5QCiiADksDCZ7/mL2GWgU03+Ed05GTHh3tmi3svt7zmIIXAeHAg4ppUIFhVhh4Uql
         Cugw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CcFOjNnK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id az19-20020adfe193000000b0022acdf547b9si397636wrb.5.2022.09.24.13.13.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Sep 2022 13:13:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Kees Cook <keescook@chromium.org>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH mm] kasan: fix array-bounds warnings in tests
Date: Sat, 24 Sep 2022 22:13:27 +0200
Message-Id: <288e31a608ba707ea6de47fc6b43d8d79bb2d252.1664050397.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CcFOjNnK;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

GCC's -Warray-bounds option detects out-of-bounds accesses to
statically-sized allocations in krealloc out-of-bounds tests.

Use OPTIMIZER_HIDE_VAR to suppress the warning.

Also change kmalloc_memmove_invalid_size to use OPTIMIZER_HIDE_VAR
instead of a volatile variable.

Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan_test.c | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 71cb402c404f..1d51efe131db 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -324,6 +324,9 @@ static void krealloc_more_oob_helper(struct kunit *test,
 	char *ptr1, *ptr2;
 	size_t middle;
 
+	OPTIMIZER_HIDE_VAR(size1);
+	OPTIMIZER_HIDE_VAR(size2);
+
 	KUNIT_ASSERT_LT(test, size1, size2);
 	middle = size1 + (size2 - size1) / 2;
 
@@ -356,6 +359,9 @@ static void krealloc_less_oob_helper(struct kunit *test,
 	char *ptr1, *ptr2;
 	size_t middle;
 
+	OPTIMIZER_HIDE_VAR(size1);
+	OPTIMIZER_HIDE_VAR(size2);
+
 	KUNIT_ASSERT_LT(test, size2, size1);
 	middle = size2 + (size1 - size2) / 2;
 
@@ -578,13 +584,14 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 64;
-	volatile size_t invalid_size = size;
+	size_t invalid_size = size;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
 	OPTIMIZER_HIDE_VAR(ptr);
+	OPTIMIZER_HIDE_VAR(invalid_size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/288e31a608ba707ea6de47fc6b43d8d79bb2d252.1664050397.git.andreyknvl%40google.com.
