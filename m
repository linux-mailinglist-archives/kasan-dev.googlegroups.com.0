Return-Path: <kasan-dev+bncBCCMH5WKTMGRBF4Z2WZQMGQE6IQHKGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 15E8F912127
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 11:49:13 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-37597adfab4sf17428515ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:49:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718963351; cv=pass;
        d=google.com; s=arc-20160816;
        b=vH41MLGCxyFsh9LYUsPZXt4jYj7uerCOwvAKOQZAAc5N7vKS5aVV9GUexR+Ot5k0EK
         DkD7QxnmKxgFxEwJ+1THY1ELGFlTxsWWTJrxMeCHhtC9o+W0xqBw4cdppRu60B+cwSlu
         4lJ/tX4TwWxE2C3wmOrUx/Ol7ho+p0c+VliQP3Y/RLfEY9WcgQHqaLT6/6tUdT0tYimi
         lEihhbsXh2inxf7N95GW+Drer/C04qyHi1c0Gr04tEbOQuft+88qavCdfDTNwgpGInEi
         WLS8QjnEnWc3T/x/JvzK/Jshjps4hQrBw+za9nqwFdSHGEaCTQfS7+YwtyDlKvAZsbCO
         H5uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=FRp/3Gc1F6zWhppxx8juRJJVy7z84YUAaQnz+M0kw1o=;
        fh=Yq46GmZGrzkisuGgK1dAgWtqduvTJW/XgX7a7yBq6tg=;
        b=j32HlJUOelTrhuNcHSFw5OP0QnEUn9u0BFVdzkeDN9GXlbLdKR2rqWZsi7ZszFW7z8
         qe58oltn2ZIGVwTbryaD3rBEqzAqlwS1dA3QQa/QHQ9FJ01DpA0T8Cz7vF0QJutvhNcE
         M+2oKUTlJd23K2Wo5gYrYzGiaL4kyIiiS+KY4pYUh/mpdktUhA6NQYNboLW/CAcN5ImZ
         i/wUWYeA0nz/UUsdC1INRmbcU2/Xknv0+T7vdh6xZp4vrVCLfAHnhxpL5aOFru3JDBY4
         ckGLAmbjDT07LvbodmD1OAPX0uiBpjORn0OofYwj70QS+yD6avvhMqF0EJcsrf1lRT5G
         fTjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FWIlXmX6;
       spf=pass (google.com: domain of 3lux1zgykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3lUx1ZgYKCT4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718963351; x=1719568151; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=FRp/3Gc1F6zWhppxx8juRJJVy7z84YUAaQnz+M0kw1o=;
        b=vmBxJnJ+d9FkEqEalb0CszOnG1pjY/FmK3TX3cdBPAAuzK2Qu3mVqFp6fINkDOObdA
         nNfcZL7ykste1HOEy327vuCSLCHBx7CkRJeGCM7tB/hh6cbpwR+GI0GCJW6kHVY6Jmi/
         E0fBV5FhBORT6jDpiCv21HGHdUruCBKLWk0+ygyYybynUoGd2cvmz59MjT753GXijD6e
         BbYchURoYlkevrJX45xrDVq3y5jNHa0+rEwekj0PJDwHMBGrNsW+RwFMWuJHFZEd6rTC
         zdmpy2mmP4+862ZbZKk0QhNqRBG4VZYlKVPXq3X4g4VRkGzC8QfxK4QxwO3ccZeOFUtQ
         riAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718963351; x=1719568151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FRp/3Gc1F6zWhppxx8juRJJVy7z84YUAaQnz+M0kw1o=;
        b=kdQ51u+EjwpJ2VVu/2GzXA0PunLhqbOwUVrGp8DQl9zPEo1pGR2vMihr4fQAjg7yNn
         hTYLeaEcIoraZ7WtNC34zy/InVVFIQaanXKH/bguGwsmDe6zRRMj9zbfmn6LS/XzGWzH
         41YRh0+otFTxSyjcPDh0bbiHqLxBsOYEmTlhWsj5h4qd5Kj8lbyAtzroZckuAby5HqSa
         WOiJaypDa+wyr6XDV6k6VxHi8Mt+F1kULyyXpERUgzk7RolRtxqAqEoVy8hzFnay53Np
         LhNF4zY+wSyf/B0pmkoNs/MzunY1vsU8gP9heTh1JOc1r9m44lE44GLbU/WrK5r/H4B3
         rDkQ==
X-Forwarded-Encrypted: i=2; AJvYcCUhztVFJF56LiB93Teiq3QIAGPab2kNQ/6hzqpirqvy9nxrgljDucAGlu7D10hlNUIRUHMF3YUWq7YZuhoDFJTCC1nyhWZcGg==
X-Gm-Message-State: AOJu0YxiEyHOFykvFv+zNHT5w6Col/Nc4keEsTE+RwXShnB3ghDD2mUk
	5goO6il5EuCoCxSxflve0guBQfetTjld9bRc15xVvUIhXRmZMkBI
X-Google-Smtp-Source: AGHT+IG3WZWmJWboIM8gNnAQZgEpVS1JQ/1YiUkeWnE4+eqXwfMjJRdU+/8YJ3WSTjLgNB0cZ7h0LA==
X-Received: by 2002:a05:6e02:17c6:b0:375:8a71:4cc1 with SMTP id e9e14a558f8ab-3761d7805c3mr91394905ab.32.1718963351585;
        Fri, 21 Jun 2024 02:49:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1b08:b0:375:8a14:107f with SMTP id
 e9e14a558f8ab-37626ae0103ls14305545ab.1.-pod-prod-08-us; Fri, 21 Jun 2024
 02:49:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUo0WWijFnQJ1xPJIsDURVE+pu2bMAJwPnqJKkRJJbMc4UrreuuqXTth3RXisRPXrGzYXjNB5itOEVlRwlUHTRO74ru8hqcB1Q7+A==
X-Received: by 2002:a05:6602:158b:b0:7e1:8a93:48ef with SMTP id ca18e2360f4ac-7f13ee8ac9dmr948951739f.21.1718963350375;
        Fri, 21 Jun 2024 02:49:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718963350; cv=none;
        d=google.com; s=arc-20160816;
        b=IzY0RujL7XBNEKPLAXjPbsZS8q8Y+HfEFgb4gMt/ysxD7/ZBH3E35NFltjxXmjVyM4
         PFF1JVNvuR4F8wIjvtMiR5e2KF1JyP0LtkjvRyjNhUGoXODpwE4ovi2pq+0RpzA6IEUE
         xMDn+UvuRX05Oq+umWhRIjbx4Z10UsFUPdLyQknVWvvBBjpOVN33uWxxNURaCCP4643q
         oEAsKhXkAzkLz8U8U5ma20/ieLuEXcZW4niL4ZUhkbf9p3BkJtV9UuTdpsbWp8VsRr72
         A4lzTNnSr3xnINZ6G8UtZ4CkU8TTrBA2jcyWmk753Pi8pvGtYp+EJ5/Gam0idnJIOG5I
         9S9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=8eL/gHuBXiJhQGsaLE8w3CglcJQmq/s11xOk2yS5eag=;
        fh=5s1TQj1BM0orWjl9XJbuE9z11hHm0NSVSFcSAHCXqPs=;
        b=TVXMQkZ3mC6Lo+8dkl/xBO1o3/3+s5lfbZ+HTpQm1lHN/jJSuZW5OPqo4oHeU4j/MD
         aE1wdl05vAqf+AMq5yG/YEyyHGbJ3qaROOUTu6ScW5s5v2gWWP9+Jz8xnHlMpbxlx2I6
         JDrYNMTUlsD7zS4qW6ylQNAm2uMzx56Y/ptkCYcMatKtwB7UtQ9/XCgzLyVv4TbDIHtT
         zW2AR1jEaCjwSucwNrEB4DuPvzdJaOZEwbvgl5vtpAQcHFEB3rpCQGUHXTDERwQVo7C7
         z/Vv6X87rzCH0jaz+iMkgqg4EaOvn7qSG42agpJsCMNrJrVffNyslgY/PxMTVhD5iQqn
         Yzxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FWIlXmX6;
       spf=pass (google.com: domain of 3lux1zgykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3lUx1ZgYKCT4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7f391d4edfdsi3613739f.0.2024.06.21.02.49.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Jun 2024 02:49:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lux1zgykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-6344d164c35so34790067b3.1
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2024 02:49:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWOiv3FIGDs0kjMezzhoRznvp58RevvbcLdVFBCtvCMxa+U8RS83LTCSLZalRfLM08a8CpytxII3AsZfSfiiCzLDeRfMBpY7ZqgbQ==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:485e:fb16:173e:13ce])
 (user=glider job=sendgmr) by 2002:a05:690c:6a09:b0:62f:1f63:ae4f with SMTP id
 00721157ae682-63a8dd018b6mr14369697b3.1.1718963349823; Fri, 21 Jun 2024
 02:49:09 -0700 (PDT)
Date: Fri, 21 Jun 2024 11:49:00 +0200
In-Reply-To: <20240621094901.1360454-1-glider@google.com>
Mime-Version: 1.0
References: <20240621094901.1360454-1-glider@google.com>
X-Mailer: git-send-email 2.45.2.741.gdbec12cfda-goog
Message-ID: <20240621094901.1360454-2-glider@google.com>
Subject: [PATCH 2/3] lib/Kconfig.debug: disable LOCK_DEBUGGING_SUPPORT under KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: elver@google.com, dvyukov@google.com, dave.hansen@linux.intel.com, 
	peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FWIlXmX6;       spf=pass
 (google.com: domain of 3lux1zgykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3lUx1ZgYKCT4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

At least on x86 KMSAN is seriously slown down by lockdep, as every
pfn_valid() call (which is done on every instrumented memory access
in the kernel) performs several lockdep checks, all of which, in turn,
perform additional memory accesses and call KMSAN instrumentation.

Right now lockdep overflows the stack under KMSAN, but even if we use
reentrancy counters to avoid the recursion on the KMSAN side, the slowdown
from lockdep remains big enough for the kernel to become unusable.

Reported-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
Closes: https://github.com/google/kmsan/issues/94
Link: https://groups.google.com/g/kasan-dev/c/ZBiGzZL36-I/m/WtNuKqP9EQAJ
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 lib/Kconfig.debug | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 59b6765d86b8f..036905cf1dbe9 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1339,7 +1339,7 @@ menu "Lock Debugging (spinlocks, mutexes, etc...)"
 
 config LOCK_DEBUGGING_SUPPORT
 	bool
-	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT
+	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT && !KMSAN
 	default y
 
 config PROVE_LOCKING
-- 
2.45.2.741.gdbec12cfda-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621094901.1360454-2-glider%40google.com.
