Return-Path: <kasan-dev+bncBAABBEPMXG4AMGQEJ3EXYIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AEF999EE9C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 16:02:59 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5eb584e7aacsf169569eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 07:02:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729000978; cv=pass;
        d=google.com; s=arc-20240605;
        b=BoDoSaX+iHxZrouPI+koft683w0w5GCJumtSA0ZUGh5/+Yvg+bJsXfJQevPj8OgVf+
         +q2AHyWex2c5JV7mINki/j3fjWw7PIGltJ6vXLRz9XMj+sF3OAblB/K9Us8tiTCZFITD
         m9y2WYBnyqUvhHo35eZpc937rFuvJJI7y0ZrJPZPZpCK+bI4zEca0waQ5d5G1H082aXH
         wfJ+ExZhQ6OTVeKiPzdyrPCJKUpXSeapCaWzUa0RQuLhoirX1/9j0rjtZ8CZtMQ04DHM
         NznSMhdPXEZXSi13HjHHLLoFxrzQ979wpXgoXxaST7UwPEKdOa3X66fc2L6J0XMgAB0D
         1C7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=l7dDRvvJQEPZDLO2ljStrPO76pBf6FxP+IDtMxv0wjU=;
        fh=YMvUX4+VgJAWnofR3W4Aa4T/zI3RNIVyAl3ZAI71OWc=;
        b=CJ0Gh0boFEdjo5PBL5a9dbeTW0V0Mcry8VqSqImvxAzBE9exo/xfDc6l6hJX9U7Bv9
         clemuQjPKKP5IMmlYJsQl0mFRaJae6Z5Sz5pH26CopUodg/kKVXEvZNg6HDAxiwkw+il
         xiMQDAicbezOIn7FfiHjXHZK6VS737JCkD0uwCBYtaA4hTRXb2oLOrhAnC67Ma2UfNId
         33bZ+Oixf5cG6vcU1r7oC3q/HU6hB3v4aL06qlmcXYsYTnh6oHyf0akXYjKw9f255dLM
         eorpzHhwGsmnqKuESTWkPMTf2zgtvR28zJNpbpAbKI/SkORWljRiw0xFo5skVWSXUyyK
         UuRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tttturtleruss@hust.edu.cn designates 206.189.79.184 as permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729000978; x=1729605778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=l7dDRvvJQEPZDLO2ljStrPO76pBf6FxP+IDtMxv0wjU=;
        b=EpnAHP4zTXgNDI5mvFbFmO/sYrWSJ3qL9sVhRIItUh/1gEbR95IiErJwBZWyhug5hd
         cAQXSCGiQUa0yqnLKmcvZlaS1uHgQkEwklw5KnLYwRqcnIvh+wT21KCM2oH4btD+1ZS4
         ZoHtpsUv473k3Uv5vHNLQhVyTQ7uonn76cBZVU7Y4LgSe1d+DM4x7oCAhXVOMlSjhFWJ
         KEJmNLYr7G0pYvYvcb5xrw0rO7FgWC6y0bEdZ4pYQ7Kcvuf08s/UlZoavA1Uv7dO0InA
         mp3SiXZ5BHZaXS8Z6HvsKIv4OMtLfQc7/zGQ4a8HaYAEOZYkWHKQTo3XviyFnwb3q7GJ
         Kosg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729000978; x=1729605778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=l7dDRvvJQEPZDLO2ljStrPO76pBf6FxP+IDtMxv0wjU=;
        b=MT8uxgVAI1Y14ep2VcWc7NQTmkDGGpP9eyK0kBGUYCzjXGa7eV7n4Fgc8NM6YtPK50
         5TXhwHsTjzsJ5rQAqD4iNvPzADdyOzWoHKe21Fc00zIS9YpuYrRZMeDK4dC0rWrmgVRQ
         XoqHoylThiVmX+bFoY01nNDpW06U2ptuyeQ4kdJMvaiqCV40L+CNGX2NsQdBaob/WUxj
         Fq1h/lJX0o3jNQMkx/g4Hedc9Ly/aZ3fjWvW4LmM+tHUC1cMMaJCTfhMdTD5rii8eSXX
         mP7qna129Wu99jaOTp9brYdcBxVb3bTT7DABtNyv3pT+vSjM/hsISLsPARkK2zqQ2F0e
         o2qQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzC4wCtioz2NiSegv+Y6g8cIIrMtW63qLnfYwYd2ELFpamFh3uN6J0NA9ZWHpM10gkGVwwQg==@lfdr.de
X-Gm-Message-State: AOJu0YzCfcmsIdGfQYLjDxiBN7D9bZjs5BOpQH+YgRVuHH1AbXYxcjQQ
	GryAGKASQxhrOYsdnw2JJdhr84yKRqHLY8/63q27pYsdp1yrQFhG
X-Google-Smtp-Source: AGHT+IFMq3OZs/0M8Uqr07cnByPHXg6VOQ947ABGMhrQZ5EO4z0JyZy+jY2ckH+Vbuv2cGFfu8Ak9g==
X-Received: by 2002:a05:6820:1ac1:b0:5e5:941c:ca5a with SMTP id 006d021491bc7-5eb19ed9b9emr9780806eaf.1.1729000977524;
        Tue, 15 Oct 2024 07:02:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e9ad:0:b0:5e1:c3db:6975 with SMTP id 006d021491bc7-5eb5ae1df3dls4508eaf.0.-pod-prod-02-us;
 Tue, 15 Oct 2024 07:02:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXUk6bPzTnDvgUn5patdp+p1oSPm5laGiEpPEZs1+aaKcCQQlcEsGu3V0Q7uMT6g7oVGic4F8v5dUk=@googlegroups.com
X-Received: by 2002:a05:6830:2111:b0:708:d860:e51b with SMTP id 46e09a7af769-717d6423759mr12607561a34.15.1729000976437;
        Tue, 15 Oct 2024 07:02:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729000976; cv=none;
        d=google.com; s=arc-20240605;
        b=C7Svsb85JgvchGTOQ86jYxcYk8LEKZ2bbUSizvawfM6Pz4pQHl7powT2TlEdTsP9Iz
         QQCJy8cEwYOuWRV57N0mfIV0JVzCACPr6cPo39gAqYJzkVFcdhyfXgmojxHfgOP+HH0s
         xYwT2wTujG3VkpUqO8cCv3CjFsu705hpvjKHZAxu8mxs7Lc6QUdTxMWh+PS0VmtykIiy
         ci96Ghtacqv2pigQ5TkffHbk0y9wEatPmp0mKPVSRY4bSBqvtAFlyW7JV7XDYAzZ0bEf
         /tN0pmaXOgQA2Pwq2RZ30xGhMCebSKMqqDcdU9leH5aiWBB8ck40FLYViOBeJBA/41/g
         +xGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=FkDRrK1ZXE3fiyNMu2ZrwRGmV0nt9Z0LtZwXAlN/TLo=;
        fh=Iz5k/f0TF1+wq5YmnL8a/uPqJFuoqXmaU8CzWPsyW7A=;
        b=A1qvYeGPkhcfkDqkOPyKYqMN0ADipUrHH/vGvLxUJ2EOAHwYFVpeoIphMm3NqZ+fCP
         WKnB7m8UvjOcKgRBxto3o9SDysZspVR4QLVFRT+HQKK+s2H4o/0zvNO8IAEC4xpy26k5
         dgqpVuqcfiPm6Qodut0npbSt5TnvHxuj2HMvBdvyBBCTe4ii89tqNlxczQgV27jniuAY
         RYYpDcHlFUj5BhvJTuer3EiE+KRPEwh87NtUB/SZGtoUzMufdYTlnXqGwTMMKx2ghHE/
         bwzXlB2lDZ///sXtieHTIsiNEN9pFdOAAzdKwqOovRHhVBYyGxA/F87jB3tlegGUBWDD
         p3hQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tttturtleruss@hust.edu.cn designates 206.189.79.184 as permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
Received: from zg8tmja2lje4os43os4xodqa.icoremail.net (zg8tmja2lje4os43os4xodqa.icoremail.net. [206.189.79.184])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-50d7b2c07absi69710e0c.3.2024.10.15.07.02.56;
        Tue, 15 Oct 2024 07:02:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of tttturtleruss@hust.edu.cn designates 206.189.79.184 as permitted sender) client-ip=206.189.79.184;
Received: from hust.edu.cn (unknown [172.16.0.50])
	by app1 (Coremail) with SMTP id HgEQrAB3fn7zdQ5nK3HMBw--.15759S2;
	Tue, 15 Oct 2024 22:02:27 +0800 (CST)
Received: from localhost.localdomain (unknown [10.12.177.116])
	by gateway (Coremail) with SMTP id _____wAXIULydQ5nxbFIAA--.32737S2;
	Tue, 15 Oct 2024 22:02:27 +0800 (CST)
From: Haoyang Liu <tttturtleruss@hust.edu.cn>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>
Cc: hust-os-kernel-patches@googlegroups.com,
	Haoyang Liu <tttturtleruss@hust.edu.cn>,
	kasan-dev@googlegroups.com,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] docs/dev-tools: fix a typo
Date: Tue, 15 Oct 2024 22:01:59 +0800
Message-Id: <20241015140159.8082-1-tttturtleruss@hust.edu.cn>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-CM-TRANSID: HgEQrAB3fn7zdQ5nK3HMBw--.15759S2
X-Coremail-Antispam: 1UD129KBjvdXoW7Gry3WFWrWFyDGFy7Xr4Dtwb_yoWfKFbEyF
	WIqa1DAr98AF90qr40yrs7Xr1Svw4rWF1rCayfArW5G3sFywsxJF9Fvws0qr4Uuw47uFnr
	Crs3Zr9xtw13KjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUb3kYjsxI4VWxJwAYFVCjjxCrM7CY07I20VC2zVCF04k26cxKx2IY
	s7xG6rWj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI
	8IcVAFwI0_Ar0_tr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UM28EF7xvwVC2
	z280aVAFwI0_GcCE3s1l84ACjcxK6I8E87Iv6xkF7I0E14v26rxl6s0DM2AIxVAIcxkEcV
	Aq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx1l5I8CrVACY4xI64kE6c02F40E
	x7xfMcIj64x0Y40En7xvr7AKxVWxJVW8Jr1lYx0E74AGY7Cv6cx26r4fZr1UJr1lYx0Ec7
	CjxVAajcxG14v26r4UJVWxJr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcxkI7VAKI48J
	MxAIw28IcxkI7VAKI48JMxAIw28IcVCjz48v1sIEY20_GFW3Jr1UJwCFx2IqxVCFs4IE7x
	kEbVWUJVW8JwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E
	67AF67kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCw
	CI42IY6xIIjxv20xvEc7CjxVAFwI0_Jr0_Gr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1x
	MIIF0xvEx4A2jsIE14v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIda
	VFxhVjvjDU0xZFpf9x07UP-B_UUUUU=
X-CM-SenderInfo: rxsqjiqrssiko6kx23oohg3hdfq/1tbiAQgLAmcN5cAjpwAIsD
X-Original-Sender: tttturtleruss@hust.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tttturtleruss@hust.edu.cn designates 206.189.79.184 as
 permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
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

fix a typo in dev-tools/kmsan.rst

Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
---
 Documentation/dev-tools/kmsan.rst | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/kmsan.rst
index 6a48d96c5c85..0dc668b183f6 100644
--- a/Documentation/dev-tools/kmsan.rst
+++ b/Documentation/dev-tools/kmsan.rst
@@ -133,7 +133,7 @@ KMSAN shadow memory
 -------------------
 
 KMSAN associates a metadata byte (also called shadow byte) with every byte of
-kernel memory. A bit in the shadow byte is set iff the corresponding bit of the
+kernel memory. A bit in the shadow byte is set if the corresponding bit of the
 kernel memory byte is uninitialized. Marking the memory uninitialized (i.e.
 setting its shadow bytes to ``0xff``) is called poisoning, marking it
 initialized (setting the shadow bytes to ``0x00``) is called unpoisoning.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241015140159.8082-1-tttturtleruss%40hust.edu.cn.
