Return-Path: <kasan-dev+bncBAABBYH5WT5AKGQEXAV6IBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id F29572580A4
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:09 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id f8sf1349968uao.11
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897889; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y+LUvGVCahxXoqEh0itGQqbtEqeKQd50oXz8+3LMkWXI8wWG7SlmVZpb2KeTPfYBi+
         4krLaEJ9+2ktXRlRY0iY0EALOmQ95GbjooL328/+jUL6uZEREklsI8vDXbuZ5B/spCv/
         I7s6QTRN+Wyr/gw5tYCXUiT+ck3UL57dEYhmJLQzQJm3Bt8UZNRBax8ybnEwTGKoEnZv
         HN6Le4jCOy6+xS7DaLgRj6ioLuLCa13XYF76i3XGGJuVoLL0MYIfFHm0iQGUkwrVGTvQ
         7OdBEKbpdj+I+T3FlK+hp7B7bLOxoe/XNdPE/Z4wXIxbdDKs3WoLRwImkTwiKP4BHHI1
         aZhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=9GXEZHPWDLvw1cQW64678HB96r6rjEY2EGQVzlNA9pk=;
        b=RwOl2lWVzB8lrP8HmjyYv4UvErBymtux7BjmqaPnN8woDwlJTi26fJQwqmk7xlSZJ6
         Vu5EJa9qk83INOckK6fDThcDuA4O/D0gqOAC1ye7u3+pvkw0jinHAa3C8T1ysJwJ8Ruj
         XI7R2Kv2ryUkw0DNa/AaZu5WrsD91IJEZo+uf4e/eIB8A4RUmPEY/72prFGewnTu+S2l
         BaGonadNiKEpnbW2OBt81zjpdYys0L4KgP0ySLoTBLiSC+02e4GAzb/stdvJ+vrRSpsz
         Pyk22b5CqAGv1H1GzORLJYp1EsMPjYlh7jq+wny69B1b+a4QOGT80wQufXYeUEmCzuZo
         F2/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=krx4K0jk;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9GXEZHPWDLvw1cQW64678HB96r6rjEY2EGQVzlNA9pk=;
        b=nSYcRK90ZDDDwUTn1UkCEiUNGssvzqeX2+i9pDa/iDAWGJovpoW/9ItXc6EH8Uv+uH
         7s6yTI6UjFK+igtuB4EQ3kqSjCsTCnk6T6+BqTqScsw4b6hSkM3cjhiLfzSF6Wj2n3qR
         5srJGeVK4qPgHYafH/xypq8FMNxbEITHkeljqEo3qhVl1onwfoIYTYYoXqZ2HmYoJihQ
         /jAd1jB1TMRVdk1Eipv9mW/fGTdVhT3yrgasYBg7xi1hECkex94S3uYhT36ffHfWDW5t
         w21C4Nqi5bfaFqaCmq9lFj+LTSaXFvZGy04BNGAReXyjeaJ7ereOFt42I6/aIgmQ9IcF
         hldg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9GXEZHPWDLvw1cQW64678HB96r6rjEY2EGQVzlNA9pk=;
        b=SvxdOaA/Fa/7qfDVK/5IbLnsNVm7ojbUHMEvIMdwwqnhisqIWtheTimPV5DQWyyefx
         YMgOnlI/F3FXeiuinTshdmEhgqQwFEVV0ppI8A43KRzxjgCIQskPQxQsG/xdscnTcDjH
         Z25lJF/Bn5LfjZmR8EZGcsiMrJIg6+Mq8E0gJVTFZX9aQ8r+c7LxLETLaQoAO26q/xJD
         6X3cgVjXleIuzAtEd7zWVmnCye4zUR/ybpGg2aMkVKZaetW4i0KykfakE+4Ku4qgVH2p
         YhraX33dD5T9HJXcihnmMb2kHhCl/lstGvKuR+3nwci64PZIK1z+bHYSq60R3ZWTWtob
         SmvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Vy9xyZ5hnABz7baLqoWCizQwQpbxFlLBtHCs67nG4lagb/2Fw
	EX9UpwjWkbf6VaR3KWder0I=
X-Google-Smtp-Source: ABdhPJyI1F62F024VnRwrmxJNzeuyMic4QrI/M+uPLPbgqsrWiCtmukiC31PpBSFPprmZ0vqvjcXfg==
X-Received: by 2002:a05:6102:141:: with SMTP id a1mr2390390vsr.10.1598897889074;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:20c5:: with SMTP id i5ls626292vsr.6.gmail; Mon, 31
 Aug 2020 11:18:08 -0700 (PDT)
X-Received: by 2002:a05:6102:30ba:: with SMTP id y26mr2229468vsd.122.1598897888627;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897888; cv=none;
        d=google.com; s=arc-20160816;
        b=j12Jeoyv3Fb/v9qsv3sIBrtbOaJYTN7ha7ednFyK86z/yPerN0GVkGtblmIqEZBwXL
         cTheJcESNuG4FVz3rGNbQ+MuIXRs6kZAfQz3WpUIOqYQwOLtEfsrHc7/C7CPcpJ+Xc4V
         5QktWou6q37JNdNPl2uxD9QHeC9kAWAKpNOZDa77kYMIH7d5NJJhspYZaYFcw2S60gen
         ac6xflkwu1jssXqLGjVAl6ZIrzZrqb8Q0rm60U3a7KQ4vCtIKy8Z2/AYyPi2mNUNfAWi
         ftKUoxQ5g5IIKSh+YSOMqP4keDIyhWAGnw/JPgIfl5X19XNgCuZTFiq3t90/WpySfRWa
         0Imw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=yvSc+zMhUiUFJwUhVMRNSqROrUJ6aW9EH2eUaXNq7Ys=;
        b=geyDGmPTjqyx+t0Fs1lqPO6vO9fqgtz5R7uACkBa0E+hvXLjBIYb3YK10sYqtDM114
         oWh//qtVKJDlPymp7DnEjvPMzoQaJZI5/i55t/NAXOE+W4LOBnlNGeIcMqVIkf4QOSO2
         +eA59Q08lWJasSXpSfshM6fJPi6oi+PlqgtbayW8huDDdyvKU8pRqylmgESKqenbzlkq
         KwJQDQNZ8WSIND3os77iN9XsGpbve51dsMLDRzidR3yhhiodUCHRQntduF0MpJAV3LnD
         Pz7ytLaAzRngXVUP4docgy8UEcVsPNBJrxn0LJBH4P0Kk+r7yEVlm/dgbJn6jNw4KL+v
         /IfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=krx4K0jk;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s10si77220vsn.2.2020.08.31.11.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9A0E621548;
	Mon, 31 Aug 2020 18:18:07 +0000 (UTC)
From: paulmck@kernel.org
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
Subject: [PATCH kcsan 09/19] instrumented.h: Introduce read-write instrumentation hooks
Date: Mon, 31 Aug 2020 11:17:55 -0700
Message-Id: <20200831181805.1833-9-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=krx4K0jk;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Introduce read-write instrumentation hooks, to more precisely denote an
operation's behaviour.

KCSAN is able to distinguish compound instrumentation, and with the new
instrumentation we then benefit from improved reporting. More
importantly, read-write compound operations should not implicitly be
treated as atomic, if they aren't actually atomic.

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/instrumented.h | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 43e6ea5..42faebb 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -43,6 +43,21 @@ static __always_inline void instrument_write(const volatile void *v, size_t size
 }
 
 /**
+ * instrument_read_write - instrument regular read-write access
+ *
+ * Instrument a regular write access. The instrumentation should be inserted
+ * before the actual write happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_read_write(const volatile void *v, size_t size)
+{
+	kasan_check_write(v, size);
+	kcsan_check_read_write(v, size);
+}
+
+/**
  * instrument_atomic_read - instrument atomic read access
  *
  * Instrument an atomic read access. The instrumentation should be inserted
@@ -73,6 +88,21 @@ static __always_inline void instrument_atomic_write(const volatile void *v, size
 }
 
 /**
+ * instrument_atomic_read_write - instrument atomic read-write access
+ *
+ * Instrument an atomic read-write access. The instrumentation should be
+ * inserted before the actual write happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_atomic_read_write(const volatile void *v, size_t size)
+{
+	kasan_check_write(v, size);
+	kcsan_check_atomic_read_write(v, size);
+}
+
+/**
  * instrument_copy_to_user - instrument reads of copy_to_user
  *
  * Instrument reads from kernel memory, that are due to copy_to_user (and
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-9-paulmck%40kernel.org.
