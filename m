Return-Path: <kasan-dev+bncBCXO5E6EQQFBBGVPWOPQMGQE2CJANVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id F2FC1697C90
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 14:01:18 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id h85-20020a1f9e58000000b003e8d54eb923sf7143177vke.5
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 05:01:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676466076; cv=pass;
        d=google.com; s=arc-20160816;
        b=1CqOhlIJGCZuGSKLgKXWKawj15atBNkTD+67kDKk5fP0a3+HveIyFNpCn+897rbWke
         97T7A44FLyAvoVMmdoVHb6OpAnWmlW++ovqFgEk4gU9aDLYbq4rCf+Ls65rOpFallc1v
         oQFpPQzBEasJSU2wg+8OSa2kn9UjMxMYu1PeInJafhYy2S33Nx+sLIplEC99bEuqjdpn
         cGXCwULX5BcwydDXoHY8DFTYvZAN1mO6S8j11dgvaZvYtru3H+RoL+V1MAiFnc3FlTM7
         5+P4Fxgv0tGje/sS4Mo1NV18ZJ31U1ntELjOs99GMRCbHRQVoMLC8a/ydn99F8vyKcbD
         9JJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+Tz+DQypgu+uicJzFjvN271UUMjYe8TYvYOSAQCd124=;
        b=ciXOg8y5G88MshC2+4d9kxMguvL4K/anhJgWH8TF1SPGBFqjTSNEF29uqIZLC2Vk2i
         MDqlxJ5WjrRqG9qYlkKsSOsSubvpqIR6ly12I+GrVWreC+9KvAaFd8mnKHiA7vACFzKv
         KXNIWmAsxbj+2QKUmTIEh0mvCqSZnwnasMUllop0mz2NKztwJcq39b7V+4YIh/qT+fxH
         /CZBcmqt3qtXnOA4Ta7knEA2x7/KX6zyvXKtXn0YNdvizUk4GiwSY6HsX5GkUsVNZTmm
         CTMAxwApSVLGSCBTRUzisXbUk5KWmWGPwrbYnIpmMDfDlx95AI+FSYWiyXznTVkpUzTx
         dGeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u6ljbQgA;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676466076;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+Tz+DQypgu+uicJzFjvN271UUMjYe8TYvYOSAQCd124=;
        b=BmUGSIooTg/9LGHQ3XYZk16gRBZM8GzKJ6AmZHRuSvs8UcIJ2WrlLrA/hA2/j7F//S
         uANDA2cCzYXgAoXl449M5e5qylGp+7dMQbX0zFzpOLWLVz5YcQLDd+qYswXheDQMFRok
         S2+5ksGKP47T0OOBwL9Kc5D32EhxNi+0M8t202/OWfK8/mSoSmALPvx8HS8E53GBC0hL
         TtPZLjttvHD5Ep/fZcDjMirg8IbUEbXaGQVs3DyaMYm3gGp7gX+TveQjhDuzu5bfTNf/
         JkT8jSuq+wquUrGDLrZNZHKY9R4kyobC0MkOqrM3ilX9i96DhBW3siYZ74r+WU6QgazJ
         MYzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676466076;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=+Tz+DQypgu+uicJzFjvN271UUMjYe8TYvYOSAQCd124=;
        b=jB6KyEZWFhpOWZTp26XG274zdpSHfoa2yaRDssv23VxDoCraWCnzizESL5rO7DeHUL
         Y6wfwz1A1o0WY4OM362C/hKzPxS+L0k6w+8BNBgIEWiOTPBkX9i4mjtyY6jfajeT9kxc
         ljHXBorqzL37MBxQDiEOpwGEJdB+m4Tis3PcGOaIDy8xWEBBdKM0+2KFXabtA6Dad0Pc
         Ugn6ngYwAqUnINwqajQCZYduZJ3AiptZn4VkhdN0RVPd8OKLweeRfyZWxV2K8zN8MbWm
         3N6sMfigFT7bbIRVVaUOeh5q5amyO6+uOmKvTjx65N8rID7ETLj60L8TrjEeWagEafsl
         hSOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU7liQqWnKwdMVhmo/+6SEA6Gvsa1v9FHqnYSPTFs9gPXkgMiBr
	JcAN+KWeu0jlrHqSwigRn8w=
X-Google-Smtp-Source: AK7set/ZNJHbIOfgKUNn6vXD5caJvZHW72zAH9QtOId8lS+s5puHKlh6ETGiJjswWtnQf6Jx8BDt6g==
X-Received: by 2002:a67:f884:0:b0:412:4efe:a786 with SMTP id h4-20020a67f884000000b004124efea786mr395255vso.17.1676466074698;
        Wed, 15 Feb 2023 05:01:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:4592:0:b0:401:d1d9:4e72 with SMTP id s140-20020a1f4592000000b00401d1d94e72ls779969vka.5.-pod-prod-gmail;
 Wed, 15 Feb 2023 05:01:14 -0800 (PST)
X-Received: by 2002:a05:6122:2188:b0:401:b10b:a1af with SMTP id j8-20020a056122218800b00401b10ba1afmr2188066vkd.10.1676466073975;
        Wed, 15 Feb 2023 05:01:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676466073; cv=none;
        d=google.com; s=arc-20160816;
        b=qD5qUvaxa7YUJjGmNf9d9yOnC+UOE7yWaHNqQ/Kk7f7NWcxWB0CLwtcPFYO+PWezQO
         7WOvoSNPZD3Z7ErI1M0m4aN+q/jjd4kDYoc4GQWksFTAlkmIlIRarKBgDlfzCr8yoUVk
         8CxKGiGcpZYL9x0+g2vAFcXNVq+zudJm/mU3+HQy39nqsCB6TatNgecn7PzpUM+ld7Hw
         nISCNYMvmoo1lFqhQwQhVxHZ869XYE9fvz2WTKHUw+e7/pGz0FG3QiJjSTpq3FT88GiP
         QMg2Qbh63MbfFFpK4J9IaO0MNpMeHbMwPA1xLyOdwwq9DJgGOf63FCePLD385yRrg5wo
         NXNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LlL1XccJ9W7u9oEjuE1n8xFo22cK7tQYzezyENp4RVg=;
        b=c7OQcWRPh/MEQvihJ58GJ7rEgl/1iWruQl+7QYx05ahPokf3Oyzc88RgsbvSMtR9kt
         23SOLgKPw4ORURoJbtnLr5zI7S32VgeHshO6DpTNr6lenaXIG8fSG4EqS837ugshVJyO
         XwwZjnEZ0KTpbO/07Q6NQXce237KawbCkZ4J84nZ4KWUdT1Wnl0zB8fvXBdFZ6qhx2Sc
         j5bQJDDoRf0eW6SNn7ruWqFr+Da7KLyT09TFmb5soSbb63hJEyYzBtE0eSB+19oz3BCS
         KHyVkIFCYYexQ+6Ymg6nF3WmMtW+rtmvRegm74jZsKtQunjsI3f0wdW7OQeqUFRrhg6t
         DxKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u6ljbQgA;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id j2-20020ac5c642000000b00400dba9ad27si1410312vkl.0.2023.02.15.05.01.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Feb 2023 05:01:13 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 82E6D61B91;
	Wed, 15 Feb 2023 13:01:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EBBA3C433EF;
	Wed, 15 Feb 2023 13:01:09 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
	Marco Elver <elver@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 0/3] [v2] objtool warning fixes
Date: Wed, 15 Feb 2023 14:00:55 +0100
Message-Id: <20230215130058.3836177-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.1
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=u6ljbQgA;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

These are three of the easier fixes for objtool warnings around
kasan/kmsan/kcsan. I dropped one patch since Peter had come up
with a better fix, and adjusted the changelog text based on
feedback.

Link: https://lore.kernel.org/all/20230208164011.2287122-1-arnd@kernel.org/

Arnd Bergmann (3):
  [v2] kasan: mark addr_has_metadata __always_inline
  [v2] kmsan: disable ftrace in kmsan core code
  [v2] objtool: add UACCESS exceptions for __tsan_volatile_read/write

 mm/kasan/kasan.h      | 4 ++--
 mm/kmsan/Makefile     | 8 +++++++-
 tools/objtool/check.c | 2 ++
 3 files changed, 11 insertions(+), 3 deletions(-)

Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Marco Elver <elver@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org

-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230215130058.3836177-1-arnd%40kernel.org.
