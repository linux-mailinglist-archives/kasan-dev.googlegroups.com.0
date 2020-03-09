Return-Path: <kasan-dev+bncBAABBONGTLZQKGQEYXPJ26A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1286417E7CD
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:27 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id v11sf1085107vsg.4
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780666; cv=pass;
        d=google.com; s=arc-20160816;
        b=hHdc3KyQhpKXLZ10UFuCj2sUKOjWAv4RsMPXchR0F1y/xZObNAQlphEyhK+oFNn+KH
         qXxrFrr34sPcLfe85EytoYVNBzKiFILjXhZCZHgm0LkxWeKjuFmKG0UX/j7WsJ9WkQ39
         9Zjs2OUuoGWuMlqDEzl46XVC6wk5rvcmYr7Ke65Z4ms/cJ1f982Jz52whoYVDNRhNxZ+
         c3IBOPlaZRlUtzJH7rkXnUok1axHK3g8t1O+isKkaps+bBLYgzYNRMvudq9I7ZuvAG0Q
         iCm0cDtHV0YIWbgj7BYXNHhiS8Bjpmitr8MMfbviFBcDIjd9CBoY+JQMD9p9zf5LKKGW
         QtYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=xiVAY/IfI/MUQwg1mQtdvm1nIkJJHpjHyyh/4JwJAKQ=;
        b=P+aeghxBCU+VyGc7DvdiFA8qIXZTqH5QctPe2EcYeu8OvFKhlL9UYOuXwxltBef4mj
         B/+33xyIbGtI/zs45zJeNf8/Ao0wQGFBReffrfVZbJif8qogtev2gx0jv0d2ZAt9wZ2Q
         RjadCv5UNqT2wuykJMAGwIUq7zI5Ney4mc/kOLZF06hduhTBxAKqlKVLSv9Ksim+FXL9
         iMzbscP8xdUdiP/owPdDQpgOhk0WA4PCH4TIOJHuRdwKKGuM65yKWqLfG8e39rqgifRF
         vRvn9dSpYfzW+FdRkUWXM+nN7/GIoUC7wNUppzTcZl7kXBH1gW+eHtWJQzLp7H8yqEu7
         LzGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="R/Ut1NOC";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xiVAY/IfI/MUQwg1mQtdvm1nIkJJHpjHyyh/4JwJAKQ=;
        b=W5uIGGOG6qNYpNJW9zlsn5UO691pJFITL6XS2DaGji26xKhKrNJzYgjaWR1uaGSTd/
         tmqNSOGjLi9MgJOGlRQ2Q4Q0nc2agk845UvfgZT4zVYbyTICGWdfEs7ZgO6U9DCi5Mc/
         mTPBoEP7etcuGVdtbT5pe1Cf3uOL4yqWWeGL/gxslwpikyJiYYSZGInifwJDF/MPLyd/
         nnTAttYeY2HrTxjqTANoMBZvj/E0NR92+m9EOEyCMaHHSg2kEw/88hkzxHnDmUlfHxgI
         IiDUkoFZaexJhlVjAqtyjOmOubyaj7BLRwtLpn9W1VoiJb7AKwWMUYABwbZc0b2eviya
         N2Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xiVAY/IfI/MUQwg1mQtdvm1nIkJJHpjHyyh/4JwJAKQ=;
        b=n1C7YkVgBBayKaA8W66ClV7F4j7VMBB8PiqvpIVRF4uqi+Cv+lRP0C+fVlzxEiSHC/
         vdeLohM2XQay3YLdjbiXYBdgezzjcxZLbSNHq0+a7vSn9UF8+qGbSRaa/5fU0np8mlqp
         Xxf8gucLqlAW1nNr3tH5oFMpiIpfLteioVs3nn7JFJD26oj9hQo65XYJcRD3ShsaZ7iI
         Rkzs+5eYDrCCRqYSaOvpgXjkA5+ZfnsCSt4Y/vt1fXqZ1lzNbUNZ2222Erspe8tXuu/q
         7WwaEefOTHH+GjC5SG2xlihgO/obaDDYK5nOgHuWhJouQOL2hrTs444DNJqLSkqwQqtX
         +JEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ13b30n/bwZVbboRtDB8rzxetsZ7JhMPa1teufz9XTKABR85ObK
	PukZx6Hm1bHY9Q+ogOwO6H8=
X-Google-Smtp-Source: ADFU+vt7HIpIjupFM6Tar62lN9BrbynOuSXSTgAfVrFXO5ORxiN2k2M223TjWOfKdZS7JTGRTWq8gg==
X-Received: by 2002:a9f:2478:: with SMTP id 111mr2499818uaq.0.1583780665915;
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2261:: with SMTP id v1ls856303vsd.5.gmail; Mon, 09
 Mar 2020 12:04:25 -0700 (PDT)
X-Received: by 2002:a67:72c7:: with SMTP id n190mr11244868vsc.188.1583780665556;
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780665; cv=none;
        d=google.com; s=arc-20160816;
        b=S1BGA24K+SdkXzSfXcN9+JAdbpq7f4gOzBa7iptVUIhn/mdFPGwGdJJvFiqgVz5J/B
         l8XTo5MguYNPeVJAVAGa3y4WTq22ntw3Y7P5pI0cqv3rhXLT8FRXRtLG7AIph6B6+/t/
         HrgNSdt4xSKbq95E+XDd5iAgU6AB7WhhX9Az0sv7BrkzEatkofFpGQcBCEO3zSQjk7qa
         IrUfjUM4HRSXjvl6SqAC9Y/h2+Tp9U9Xz0DJsT99FABvaSo0uRoTP6xNHZ0UT6lJ/x8r
         96GJ9kJ4jbHevWAgOrPWdDnvJKo4VHqB2WFyRcnZOFotou2v2Em97IlMNgqCicB7l3eM
         1JYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=nCzY6t2wZCLAdpVwXZygsmH/wQlko6QJgxybCjJHkNc=;
        b=TWAU3bNO9BQhmObnTrmHyk8Ix5dKymk53E6P37O7r4yWLUT7AfVsNA6qZ6MrcfXJaP
         0FzlK9GjNkIy8/AEEg/0GwKqXHR8nA9YanK8V0036WsWENPsZhvHi8lt8O8+Ek+NBQ89
         qxeJRQeZbGJWyRoXhOVGGdWWCVAwk5rTVWMEo3Dh3oEU8hQ40vkUACzH2+r74DgD1VuR
         RPTjuO0xPbEBquur2zDAdKYulDE2QbUf2i+pmXrX+jdi37Vv3hE7Jqt0R34ZUXcAvC68
         /4QZDwYcupxmkj/wiiH3ry7IVPDuXe8ofXa2YDA9NSKPU78FW/8Pkgc+JK7ZpP0HPm3k
         nONw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="R/Ut1NOC";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 205si277793vkw.2.2020.03.09.12.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5A1A924655;
	Mon,  9 Mar 2020 19:04:24 +0000 (UTC)
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
Subject: [PATCH kcsan 09/32] iov_iter: Use generic instrumented.h
Date: Mon,  9 Mar 2020 12:03:57 -0700
Message-Id: <20200309190420.6100-9-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="R/Ut1NOC";       spf=pass
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

This replaces the kasan instrumentation with generic instrumentation,
implicitly adding KCSAN instrumentation support.

For KASAN no functional change is intended.

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 lib/iov_iter.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/lib/iov_iter.c b/lib/iov_iter.c
index fb29c02..614b699 100644
--- a/lib/iov_iter.c
+++ b/lib/iov_iter.c
@@ -8,6 +8,7 @@
 #include <linux/splice.h>
 #include <net/checksum.h>
 #include <linux/scatterlist.h>
+#include <linux/instrumented.h>
 
 #define PIPE_PARANOIA /* for now */
 
@@ -138,7 +139,7 @@
 static int copyout(void __user *to, const void *from, size_t n)
 {
 	if (access_ok(to, n)) {
-		kasan_check_read(from, n);
+		instrument_copy_to_user(to, from, n);
 		n = raw_copy_to_user(to, from, n);
 	}
 	return n;
@@ -147,7 +148,7 @@ static int copyout(void __user *to, const void *from, size_t n)
 static int copyin(void *to, const void __user *from, size_t n)
 {
 	if (access_ok(from, n)) {
-		kasan_check_write(to, n);
+		instrument_copy_from_user(to, from, n);
 		n = raw_copy_from_user(to, from, n);
 	}
 	return n;
@@ -639,7 +640,7 @@ EXPORT_SYMBOL(_copy_to_iter);
 static int copyout_mcsafe(void __user *to, const void *from, size_t n)
 {
 	if (access_ok(to, n)) {
-		kasan_check_read(from, n);
+		instrument_copy_to_user(to, from, n);
 		n = copy_to_user_mcsafe((__force void *) to, from, n);
 	}
 	return n;
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-9-paulmck%40kernel.org.
