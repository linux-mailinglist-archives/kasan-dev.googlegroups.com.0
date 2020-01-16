Return-Path: <kasan-dev+bncBDQ27FVWWUFRBJEEQDYQKGQERXO4YBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1225D13D44B
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 07:26:46 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id z3sf1903217vsp.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 22:26:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579156005; cv=pass;
        d=google.com; s=arc-20160816;
        b=X4KEB7zisqmsvjCUgt0WpPF6epZMRJtDVon80yBC1Lb3zt7JC4pdvMn1nTsXZ7dx5H
         nHATZfU86SJ82wWZYBq7lO1hOOn3sdMfnzOn9IBOgtJZomjRpM+edU5ClEgsUzzRTuGG
         ZgWykCPe0MXjlVYZdpBSISsDaaXm13oijYeHzLwW2ZCUm5HxZu934DJ7g26vgCJzz+EH
         NUWhR4CEmGfEoEyslEDWpq98OgE9Bh+4Gu8qg63U/PFGBTDiw+S3GOFfbkU8YNuC9YBM
         U1tNKUeuoDDgfdeZxGNea+IIF26DtzyQ7Iu9aniyDrk42vw3zXL7Rgea3r9Xzg17/l9+
         IGiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0qMQunoMeEr7Fmddi7stqLv82qUSN26Td7Oh8c4BFE4=;
        b=QZ+vr9RD4Vw6wuKuMvzJNtW4DMyBG/tGELIPKxfhEUbLLajW4kvnpMAQTDAU9wrhJM
         GBEZzshavgwGDAHIV3uN/hM/in7U2QS5JWUNV5/hbOAIRbVah61eAi4+vpzFBqolORZd
         aFSVJpvfcpJH13hB30WUxj5DIXpeu8nlAluX/Fa0/q9E5JuOCW3wQjz6EU+ZnXuNnbs1
         4llzBL6I8y7OYfu1hNd6MIagU+Dpbnhttbe9QHdhOxoH/BLmcrFnvFQUUxPCvTzM4ppD
         wHRTLrJjIBfm+xKehDtBYc9JjyQ0tSEZ2KfWM2xy4p3yQRaBLp2p6Unv7srooVxmRkW9
         B82Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=GfTRpKom;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0qMQunoMeEr7Fmddi7stqLv82qUSN26Td7Oh8c4BFE4=;
        b=kIoeqjhEDQeyoqm0er7lkepIUtB3FsQ8VoZbPiSv/7T+kEUwklI8zZvwHqV/SO7mES
         WaI42odLPZaN3aNi1E0x1rY9mQ22WHEW42E2NYZ6ba9OpaIps2ORDBH14VUFl+UaiAiR
         3pqZWUZFz3U87n5j19iX/YGsGmhkhG9awIjTQ7mHInFFcasKZEJieHBtJiMBzOT/OZbU
         4ouZedHzKDZhstJJw+07bWiDPbss237sa+FB0czCEJyE2sU26OUeudC4Df8Ve1rodVdE
         PmguhTUU+PViEL29J1tWd0xY1yWiVOL9h8WOprE+fBhz+fE0xbvZPwqoHQc2kYpPw4mF
         8IuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0qMQunoMeEr7Fmddi7stqLv82qUSN26Td7Oh8c4BFE4=;
        b=XiJATGSc2WJyZ5POagl2fFF5ll10NDxLabezJFOMkPHDXqvwOIq8BSAOmAxXPYARzm
         FbPJLVYiEzT3Lvnzyvr4Amf/1P5Ws5OqY/CT1eheB/K56H3iRYj0RSNvHzE6TWmRv+YR
         bG9gmSR545xuKQ5SAiYzVB8OWdCdJxPdMaV8xX1AsZXz2KHIMJZwsSr3GbUaqn8QdlCV
         9WK/hCB++i/HxrQQCEFXt/4pPyCTcPutZlpC4UZCSNb04LMHs7fvlVOlnuPsOEwJNstK
         F9cpu2q7+3mi8BLeymMdrFEfTfav76Teoa6srhSH4lTGRp1+P58M97fkaqupohdvZMrd
         odFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWOyHFWl8m9HHI5FmyG4nytGg8NvP/6TNL+FThUi6D2F7ApVl5f
	pGLdeD8v6RtcKtRX2GGq+z4=
X-Google-Smtp-Source: APXvYqwO6W4CxVQkInNs+bqqRI27ru2KEvk6ak2OreKqDr7zN674I6A4omN70GmpAurQR0DvaMkn/A==
X-Received: by 2002:a67:3313:: with SMTP id z19mr560784vsz.216.1579156004858;
        Wed, 15 Jan 2020 22:26:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fd78:: with SMTP id h24ls1847811vsa.0.gmail; Wed, 15 Jan
 2020 22:26:44 -0800 (PST)
X-Received: by 2002:a67:f404:: with SMTP id p4mr560026vsn.18.1579156004455;
        Wed, 15 Jan 2020 22:26:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579156004; cv=none;
        d=google.com; s=arc-20160816;
        b=WQUUKeHC5B9EQZANjtun5FheiJJkqhxBIUJ5KUuvejiaMYk7oticIfCScgShIu/3ds
         wp2KB+qlDjctYhPosSuNEM8r5XRoYEPXPh9avrTvUWxqe5YpUadaoQF2woOusYIi8/Y8
         2NMlAiHSSmBCGQ/NhV77mkAZBnAkIk4GNSDSNiuoXKbsy/Th/Wd4mKuvqSRW1eX/5EIe
         5YKNyHfIbXHXWJ46kxbCwAvMjzC15TWwf7ns5jONkDtOc+0b0nCMAaKr3Q9TN6td7Q7+
         F7R8CeXNw4RDsruDbMvtlqTo/Gb3Z0sgHvqjNApzCtelEhkTqi/Jb6z1kOxiuVN56U7T
         vEjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SI5glm9tTBFJlI56hJYs/doyA7zUbu5YUKwxBp+hpYY=;
        b=grrvVCMSDWWWpf/CTHxS2oNUM6hePDPa0GVN1N6oAPwEM0clcfwJiTTXqDjvllAnqd
         3wlkjA+OIW65ugU+950m9VebOl7zulq26DGDfiPzKkQgAEcgBI3MU9pwfEORWG9nhyxW
         BR6ILLVqaDPBNzlh7+5YYUh0KvL6CorYFJZKF14fTx6dKwUWm/rXbYS4oKs9ybfftWMZ
         F5HHHESbraQrPV4yndxLIIBV8L/OplMpyroH/CotWW/hFQJOnUOA7Av56/nWqGfCFk42
         ZUwdLLbFSNPkfXfXxYtiV0xqYjwjX2tkelOt7UX/+Y7wsP8IRzmmGq5V5VqnjPVEOqDF
         8ueA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=GfTRpKom;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id 75si795060vkx.3.2020.01.15.22.26.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 22:26:44 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id n96so1049900pjc.3
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 22:26:44 -0800 (PST)
X-Received: by 2002:a17:902:6b8c:: with SMTP id p12mr29998912plk.290.1579156003508;
        Wed, 15 Jan 2020 22:26:43 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-097c-7eed-afd4-cd15.static.ipv6.internode.on.net. [2001:44b8:1113:6700:97c:7eed:afd4:cd15])
        by smtp.gmail.com with ESMTPSA id r3sm24681158pfg.145.2020.01.15.22.26.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 22:26:42 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: linuxppc-dev@lists.ozlabs.org,
	linux-arm-kernel@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	x86@kernel.org,
	dvyukov@google.com,
	christophe.leroy@c-s.fr,
	Daniel Axtens <dja@axtens.net>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>
Subject: [PATCH v2 3/3] kasan: initialise array in kasan_memcmp test
Date: Thu, 16 Jan 2020 17:26:25 +1100
Message-Id: <20200116062625.32692-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200116062625.32692-1-dja@axtens.net>
References: <20200116062625.32692-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=GfTRpKom;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

memcmp may bail out before accessing all the memory if the buffers
contain differing bytes. kasan_memcmp calls memcmp with a stack array.
Stack variables are not necessarily initialised (in the absence of a
compiler plugin, at least). Sometimes this causes the memcpy to bail
early thus fail to trigger kasan.

Make sure the array initialised to zero in the code.

No other test is dependent on the contents of an array on the stack.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 lib/test_kasan.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index a130d75b9385..519b0f259e97 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -619,7 +619,7 @@ static noinline void __init kasan_memcmp(void)
 {
 	char *ptr;
 	size_t size = 24;
-	int arr[9];
+	int arr[9] = {};
 
 	pr_info("out-of-bounds in memcmp\n");
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116062625.32692-4-dja%40axtens.net.
