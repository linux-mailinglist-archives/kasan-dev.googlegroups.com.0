Return-Path: <kasan-dev+bncBCXO5E6EQQFBBANBR6PQMGQEJIXPKSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DFBE68F370
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 17:40:35 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id t12-20020a170902b20c00b00192e3d10c5bsf10086323plr.4
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 08:40:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675874434; cv=pass;
        d=google.com; s=arc-20160816;
        b=rEZ9Sxk+/4n6X8XeuxJgBwAaahZs9rALh1PjpM3ZjKRzllz+ZFhdvNROuYrKYmkB0G
         wF5B0HryhpcCl3nsc7wzp00+dR5EvVe71HcIgSQFHG3hsJt+CM3r/klEFMeFSe7k3/Km
         iDtmIJwtCp3VcBhKWmhDzdlbLF/dOXczBR6azNxXFV2Ijepm1kFXEkp44U/BaS5zXBqz
         yliLnXAIS4uI5jRdbfEHu8euhzn0VHo5vXDD6PvW2bl2LDzFE0GESurK6LQeL+/+y1Jb
         TFQ+XhA65yMz9SJAr2Dkgs3RIMcUAjB93OfHy+rBR3A0Nu9P1Ig1JN35OI3qMN8XptaH
         okHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=eoqLgtBusJXg9uQAbWI5956MZpUIuTaRPMWFVRHrIe4=;
        b=KGyEjNKN9uO0kv/I08a/CQiIas17SI52ty2V3IHo6DZeJDjVRafiBGn388Y4R9bRY/
         Y+t+bVALNrpw21xNiAjzWVpO6ZYld4q5yXaHtIk+SQv//FxEPSLnnXJQh4JLJjkc3dRp
         +noe9ByMSXaLeZiqMBvD9eMSmw72HRHgEM3cjs+K88BBF1uiZiobjxLJkkrR6G3Kd4Ig
         /ukWFRiXgq19YzcGqtKk1zjAxv+mSnyEe+KO5yuCG7ke+LKUibH1uW8xGPur4OqhRmqh
         3apvHS0Pz7k1MQI0yAszr+jdG4n7TABS8EmtQk7Vqx464DX+VHJtcLt0Bw7oY9LfJURO
         DU5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ewkkWjBP;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eoqLgtBusJXg9uQAbWI5956MZpUIuTaRPMWFVRHrIe4=;
        b=r9IBHdDHmEStCNy4/Ek6cv5tWArBs4An1FJkuNU+0BOlisKxGoN86s8JeAhTnvB7ry
         X2CpDub2UTKLvMgunii6mW4DkILTS4tj9oaUCnQOplJESVtlN3n+oRf9Gcj6T1+z/eMc
         VxdZCWDPswrBLiu8qchWsM4CfPmMQxKdfPaMMO9GO6P1V/p/nWaKJxQ3ER+3hzjQt9Xg
         FB34pVAPbPgCFeZvmYw6zqpkQqMLAEbQMrM3Juv7VV/joMvbD3Cc127eSNf3zxjJpow2
         /DRMISsS2CkNDlHbpXyf/M21US9ym8irjMteM/83XPCO9gANVK0WTQl5y+1Cq/NOBLB0
         5RHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eoqLgtBusJXg9uQAbWI5956MZpUIuTaRPMWFVRHrIe4=;
        b=wgDo7446ZSSssBXV8m5e2P78sDQBipJMhMiNCGQ21o4LYGeQbpJw2eniu+lVAOPc32
         UMFE2Hv3rERj20ZeF4f254vQF8GjBTVGMIqSarwsZH9HkSH03k407Y0C/EueJD/OSGER
         gHaJ1ceOVPGYIcHQVr+yUFofrzJ+pVxKC6b4WVeGT5oNbYs4WO1KunoYznJqvzglKOUY
         6HuWmJPb47NZOFJ35rNU3x8bTxSsdfT/JMwhWO5aJIRWrwwp7svIcBSRABORLATvycmC
         quVF28PtQuhqJwcXffE/ujVegx+fhrDawU1QOmBqo6nGTRJT9oKI9H5k74IQMVGugnoD
         aapg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVcNufQJ74A06OYOd0lWmGXlmB7kCHPKWoit/S2EWWrlk39oupC
	C+s/ez5JSeybENLbHvFrxMU=
X-Google-Smtp-Source: AK7set+LnXZymMmXDDZtXRq9G2LZN6/+nSmP1cDr5a6OTZ+cfchus5bKLZRPmF6CeMQ4W905SWgIVA==
X-Received: by 2002:a62:1ec7:0:b0:592:5ac8:156f with SMTP id e190-20020a621ec7000000b005925ac8156fmr1883309pfe.39.1675874433843;
        Wed, 08 Feb 2023 08:40:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e290:b0:226:e7:18f9 with SMTP id d16-20020a17090ae29000b0022600e718f9ls2991804pjz.0.-pod-canary-gmail;
 Wed, 08 Feb 2023 08:40:33 -0800 (PST)
X-Received: by 2002:a17:902:d04b:b0:199:5655:db41 with SMTP id l11-20020a170902d04b00b001995655db41mr269335pll.18.1675874433159;
        Wed, 08 Feb 2023 08:40:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675874433; cv=none;
        d=google.com; s=arc-20160816;
        b=kjjqmqsZVtosivlppplSh6NuwQnQPpUNUVliQf0Ul3O1IKb9PPxANvPCAwOqG/Gl8W
         FEgbvu5V9mRnDDb3bFX7+H1pKV9Nx6egbp+QKkIQOBQVtGE1YHQM9vALVGDWmJGLgXPi
         Z17PvyZJ7A5GZ357+922aMPtiq7qAkLDNqGT1vJQOJNIbLMGY8OPG//bJVwXi+vJbh6p
         wvjkS/tlmnpbeQ3VnHNOuJJsJlpY13jruTDBwdFtvMtWRCe6v+DXybGE1l7s8kCRaERT
         wewvy0lNIYS1ZP/hZSN729aKL9Q2iAQ3qH4e2vvUotzMf5/ajTzP61ZGn8xmYv/pnOzf
         vyJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jF2tD5+GeZfdR+u2uMsmszDgDaCRZ/+kDNXUB3+Ta/s=;
        b=FpblNN76tztboO/iUiSOHWspAH4eevg+70a9behjmtN53maL+5Nki3TJhGXvYxQkcz
         RvBj7V55B/sd1Zq/4rCDHZ2TeUS6q7fudinnXqG6Rp+SCRcmjd13lMeInIkzVDJsvGhr
         gQ346GEaARGe0IIx+c1JyPgJ5y4www5Ik+HNix4yqKrx0qvHcxX03OEvRJ7ddcHZAWZe
         ZouviRh0P7HOAxNMJsBLK9axzN+Px3ZSadAYGnI8BntzeZz4Ad+A0Yt1ZrJdHcVofSB1
         DD1Kpu6hxLYmsWoS4H8dYCFL8cOlqs+aehAAwwtKUHhfASJ524FHhuMy5OIlogqaVRfr
         iodQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ewkkWjBP;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d8-20020a170902854800b00178112d1196si1162766plo.4.2023.02.08.08.40.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Feb 2023 08:40:33 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9F37361728;
	Wed,  8 Feb 2023 16:40:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 52B31C433EF;
	Wed,  8 Feb 2023 16:40:29 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>
Cc: kasan-dev@googlegroups.com,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@suse.de>,
	Miroslav Benes <mbenes@suse.cz>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Sathvika Vasireddy <sv@linux.ibm.com>,
	linux-kernel@vger.kernel.org
Subject: [PATCH 3/4] objdump: add UACCESS exception for more stringops
Date: Wed,  8 Feb 2023 17:39:57 +0100
Message-Id: <20230208164011.2287122-3-arnd@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230208164011.2287122-1-arnd@kernel.org>
References: <20230208164011.2287122-1-arnd@kernel.org>
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ewkkWjBP;       spf=pass
 (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE
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

From: Arnd Bergmann <arnd@arndb.de>

The memset/memmove/memcpy string functions are wrapped in different
ways based on configuration. While the __asan_mem* functions already
have exceptions, the ones called from those do not:

mm/kasan/shadow.o: warning: objtool: __asan_memset+0x30: call to __memset() with UACCESS enabled
mm/kasan/shadow.o: warning: objtool: __asan_memmove+0x51: call to __memmove() with UACCESS enabled
mm/kasan/shadow.o: warning: objtool: __asan_memcpy+0x51: call to __memcpy() with UACCESS enabled
vmlinux.o: warning: objtool: .altinstr_replacement+0x1406: call to memcpy_erms() with UACCESS enabled
vmlinux.o: warning: objtool: .altinstr_replacement+0xed0: call to memset_erms() with UACCESS enabled
vmlinux.o: warning: objtool: memset+0x4: call to memset_orig() with UACCESS enabled
vmlinux.o: warning: objtool: memset+0x4: call to memset_orig() with UACCESS enabled

Add these to the list as well.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 tools/objtool/check.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 0f67c6a8bc98..e8fb3bf7a2e3 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1248,6 +1248,13 @@ static const char *uaccess_safe_builtin[] = {
 	"clear_user_erms",
 	"clear_user_rep_good",
 	"clear_user_original",
+	"__memset",
+	"__memcpy",
+	"__memmove",
+	"memset_erms",
+	"memcpy_erms",
+	"memset_orig",
+	"memcpy_orig",
 	NULL
 };
 
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230208164011.2287122-3-arnd%40kernel.org.
