Return-Path: <kasan-dev+bncBCC2JRVCV4NRBYWR73CAMGQE47RGFEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 90285B287D0
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 23:38:44 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-55ce5265269sf1335786e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 14:38:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755293924; cv=pass;
        d=google.com; s=arc-20240605;
        b=MUqk8nkFDeTqLC4VsnFJyP5e2tb1uwlXdX4+QKRIoGKIZAx89k+/TS1zqmD2rItv7k
         Qk7dx3WhMK0X5CAeSc51pyBJxBPgaJ+CNKxKOLHRtj70ayiXg5UILs0taMe9KP/QUjlO
         o9h+O1b1zaL7L3cdnr62Ek6w8bnpCceCEbyHoSIyFlAdWIbTqJasm6THnUKcuCO2pREn
         18wqtaOETXdMlK9kXVaWxTZsps3egth0FaAN0UPeL8QQKCArTLvMJ6Vem3FvypKuPx99
         qqLSsSEmFXL1f3paELMHg7SEmQus20LuUTJLm+WNfsyKcPCJpbubdOwWaFLDXJTe401t
         4rHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=4JJPgSg54xQHM3Z/WnK15rLrDXgCuAmvvW2iOZRe7hs=;
        fh=j8/YoMkT8qaB+F72EQfIbSgWxd3uAlMAxzxxOSrE+TY=;
        b=Xn1c0FdeaDt/uABKEndBdmYq+koX9w3YH3DkcVJ1uOB3Bt10N1in5+bBnhgocKpFy/
         YFzj60poxbxa61+Gm0r2Cphmndq2qXsZv9zF5Co9RhF22q0aB3JcJoPni32OogXoVA/N
         vstZbe7eEYhRcI6T4joBakJ1c4QQ9nkvMx1dmJyMCV+IOeCZq8/oP+/kbSw/wd1Llwtc
         SGAbD6Qs09SwM5kKg21o6WzCCrJv7zFkh06u4gFAANyRL7fepEzDOA2Vz2VReiwHJPvF
         mlmyvglyHYUdiouBG6f7rxOG9zNveATAHukxEZvDEiNz7LH+rzIRbAwIRScVKbaRXM39
         WSHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Hx9iEQMT;
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755293924; x=1755898724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4JJPgSg54xQHM3Z/WnK15rLrDXgCuAmvvW2iOZRe7hs=;
        b=ciau7N/RkOZMXYR9UMt+AUJoFf2Ov9Ayqh0zFLdv3CvTO70Or9fayK0+h5pSmq9Lc0
         08K1clhbkEDLL6sNur9LuPRmnTylMWeWTZyOP/AldVZfoXWf/73jL3IbwGB1DQj76Gqv
         0j6yq5unMiZzTj2uylaM76F9/dDV61qHMDd6XyjO7Uqz8dQCpJHRV87tBEUVf6WiMAq6
         sWbJjwXi9MmiN0P0SfDPFaosElfKWOKFSAPdA0ET/1dAC6Ng8VtabXKdqh4T/Sauv31q
         FP+zm37f4vd3jp+uNFKg3fxVz3IBor+VV1MtecNMGcHobbkAnwtt2KOz+kppHnpPYq3M
         XtFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755293924; x=1755898724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4JJPgSg54xQHM3Z/WnK15rLrDXgCuAmvvW2iOZRe7hs=;
        b=S15NzurhtjjB07qNylt26RBjY9onKI6VdNf5j55fPTHpjTNwuPACiOnoqI1tMlosFd
         Vw1EK+y9gSXuRDjjFpQ3BZ9Noo5xGX1tQZcB51bsBs1QC1B932m0+S2K1Q6Mn3L+97qb
         ITroa+V+dKHJd6hnDg7+pxTwLgNsYzMmEqk0j8YKa125MCAAO8yJEHW5LVCriiH+Bv/t
         LcwLG61qvgKc2OFKT6DPXERWII0wW61dcStCFkWgNJVCFIMUYDhjSXxyuIEVc99+5pUr
         Vm+OGXdXX5QUIqyth5LVxSj1oF45konICd8BabIEnoKyRTx9RrHm2Ia5Ml9XJtZrS8CT
         VpGQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWHkaR6/3G8b2o2Z2lFnZFRgwsfkGJZHfG8R4rm+vapTCN+IYPEA9hQ/1Dgq1pKUnaIQGwHQQ==@lfdr.de
X-Gm-Message-State: AOJu0YyZ7udSdVMHE5yf3jwyEUGrmnouubmS6sBn3jJ0lMylIxUzGJ5y
	3ikkAbqQHjMwo6UNxLyYrv4zT5pkGO7wsv62HlHeUobbJ8pwJdm/Dnf1
X-Google-Smtp-Source: AGHT+IERsWrYPyAC9imA1KHj8hPhh3sKaXzwARpunRUxwbUK1BvGGgk5gLW5+l4AuAd1P6gb9YLpzQ==
X-Received: by 2002:a05:6512:3192:b0:55b:9595:c7b3 with SMTP id 2adb3069b0e04-55ceeb6baf1mr992760e87.41.1755293922875;
        Fri, 15 Aug 2025 14:38:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdHV2ZpQpUsryJrI4FO4O9FL18PTYXMbFc9Hg7Bchut1g==
Received: by 2002:a05:6512:3683:b0:55c:e528:4c7e with SMTP id
 2adb3069b0e04-55ce5284d9dls694273e87.2.-pod-prod-02-eu; Fri, 15 Aug 2025
 14:38:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV56BdnaGfD6VHbXJYBGDHJxk0S7lMucU7HSgnXiEZ7VlLhEOCDVhuIm19LJnlEnLFdZSvrWBxQrT8=@googlegroups.com
X-Received: by 2002:a05:6512:1053:b0:55b:9647:8e7b with SMTP id 2adb3069b0e04-55ceeb7b622mr1059676e87.43.1755293919742;
        Fri, 15 Aug 2025 14:38:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755293919; cv=none;
        d=google.com; s=arc-20240605;
        b=ArwxLc69fLzTwk9Y0VSQB+vjuhFrGRnDRDzvDoniGBm6BqCFL64I5txoK9xaey5l4G
         ow85aeHI7aJbf2/+dNeMeTEoq7uIZSHYt4Ci30c0U+nL0HRXrWa4zER+/4WAa23vXpUB
         fN97AnOBU5ruH89vD9YXl0673lqkTajaVBgjMrzssKVaD5ucuk5GHQLjfloQoNn6dG1M
         ZGnLtk9i+LGwk1RO4z7Xv39pCnKqCGuwt0p5h2lzb8XQxpq7iQqiiPruDLCpr29GROm/
         DajAxfFPY/JtxVuMpAwIpQ4zUCYFoTBf040SuFksMWn47vv4ftOHKuDT4C+KjA2UYAX/
         GoIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Odl8SZESVhrHQmKkgQviMOnzxHTYvfzH2nuPTA/Ub7M=;
        fh=HIA5em4cBTfRbE2PwKpZ8ZPGYkn2TTuNhWHtH69P0XU=;
        b=FyJPfSMoGKzSKG5c3z16J2AWr+W75GnF+8/tASrzKcy1z/bBRWDwOi/IKMvbJBJOmq
         ZuEkVCMStiFiT7rPN/R3yEXMjPUJmN+fXbjQBsV2lukvduK13nX+fNOfQk8+EWfl4ijV
         +C2A4uyT4tz9Uxtowa06eGxYajfNpG8lCkmMjanCsZNg5DXL2ZjiHT3E0b+DsJqv3g6E
         s6yr4naRqD8O72oE5m2DYz3zrvMTjsjLMAatzQgsh6dgXI5UNgzuJiknw6As8zC5d0UJ
         RnXoKsrKSez4aoSvvN2zdUUY/B0Wv5KqbTbeopL+cc1qZyU1VCiMXl+8FVdhJZUQt8LO
         I2lg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Hx9iEQMT;
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta1.migadu.com (out-181.mta1.migadu.com. [2001:41d0:203:375::b5])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55cef3bb57fsi50813e87.7.2025.08.15.14.38.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Aug 2025 14:38:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) client-ip=2001:41d0:203:375::b5;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Thorsten Blum <thorsten.blum@linux.dev>
To: Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Cc: linux-hardening@vger.kernel.org,
	Thorsten Blum <thorsten.blum@linux.dev>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kcsan: test: Replace deprecated strcpy() with strscpy()
Date: Fri, 15 Aug 2025 23:37:44 +0200
Message-ID: <20250815213742.321911-3-thorsten.blum@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: thorsten.blum@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Hx9iEQMT;       spf=pass
 (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:203:375::b5
 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

strcpy() is deprecated; use strscpy() instead.

Link: https://github.com/KSPP/linux/issues/88
Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
---
 kernel/kcsan/kcsan_test.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 49ab81faaed9..ea1cb4c8a894 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -125,7 +125,7 @@ static void probe_console(void *ignore, const char *buf, size_t len)
 				goto out;
 
 			/* No second line of interest. */
-			strcpy(observed.lines[nlines++], "<none>");
+			strscpy(observed.lines[nlines++], "<none>");
 		}
 	}
 
@@ -231,7 +231,7 @@ static bool __report_matches(const struct expect_report *r)
 
 			if (!r->access[1].fn) {
 				/* Dummy string if no second access is available. */
-				strcpy(cur, "<none>");
+				strscpy(expect[2], "<none>");
 				break;
 			}
 		}
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815213742.321911-3-thorsten.blum%40linux.dev.
