Return-Path: <kasan-dev+bncBDW2JDUY5AORBI575KJQMGQE6EQALIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id DF2AB52225B
	for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 19:23:48 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id d64-20020a17090a6f4600b001da3937032fsf1587330pjk.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 10:23:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652203427; cv=pass;
        d=google.com; s=arc-20160816;
        b=maeb4CLXpWv3V1X3RIMBZy3Io2FgwHsT7seC5a4f/JeQefSUFRxHYVhszcdTwBDaWF
         ZuPE+bV7AOjfFO4HHaP9XtGBzNL6eqITxOe06zPuayCg0h17SatwhRZ7v3C21B7qhsUT
         3lL8IWwVwv8eWnPU3cYlgxj082yebKYoHsO/ZfggE4sHY/Ic3NU9fXOyeKPUr8AtsZ0b
         ljMoJIgBIfQTUTCKtixajuxJ4PjF5fmixWuhaKYgTJFjDUHqWIbF31A822ZPHWstY7mE
         NfK7ubdYJ/SVZlmkkZvRhRgkmwU9JYlQE3eUGsyQUTooc2p5vZTMrjSGjQqKJY5nhAEO
         ItqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=6wCUupNyOLfR19Ukqpo0e1qHyCZAAR63B3qGFm1GBjY=;
        b=ZFlCoJaw8nLgko6PD/OSTQRkQxy7wg9y4/+0w4SZsdvKNs/c1y2B4UKNin6iNnkWZB
         F/sQJ9hzTpdf5Qs5AsL92ZdGuTPt1bB8scvlVc44fZo0EeIlpQAXDv7DJK92nVIqo4y4
         HLlNEunZYjVDK84EKcnh+9kdbZ0lHVHQ8z2NsL+9SIkOGdW8fvyqlyfKvL5hBfjRO2Mh
         aw40XpuJoLaaFBP8dKf8wMvMorEYdV0b6eKyfHpzZk8dEMiAlj73h0YfcxA+ZWWWS12V
         8AZI9wWOu/htWQnDKzw0c0knNBB/H+ZdiwLbnBImbPhFzfFNBFjgqwhMyJ+kAjCi6/00
         GrxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QRrlfvMd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6wCUupNyOLfR19Ukqpo0e1qHyCZAAR63B3qGFm1GBjY=;
        b=ddYXJJIWcLjXqFJfYIy7C0jY9N3X58++khQrCPiXyQZ9Esy5X10vL781y8h2aNc4Ne
         HnHgruOfnLc2S36DRlSG7a9gDJvjYFWrs+FJgyubFlvPgSufLd8CC7VmjjvyFMtrGMHq
         76oRKFQbne1bb4eUrqfwExYMckrFDPJk6sJEEpuCpIJk2SZAOdfMhvvCqM3i8/cLK5FY
         y7AYAVypdewbIZLqB0oGZFAqdk3Gjv+OUeXir6WrExTZSheGN9uprmhoCC6IAks2ByaR
         +OjLdIjf0X2WmCzYxsnxKQkd9eGANDi51AS7ohQ/n05LLg1wu3U3Z2nvvAh25ZbxSMP9
         MqAQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6wCUupNyOLfR19Ukqpo0e1qHyCZAAR63B3qGFm1GBjY=;
        b=S+/WUqVcewDcG0+X9cCq9oSFbjGLl5crzPMpWgkAo7caDGeKp9HleqojUoFcXYbfjC
         hXVPjSpoL7wh/lfyW8LQHRj7XzBtIq2EW844a33HPSAD5lCtzwvHZ3/z4oQHDKPOKTsm
         bO1dlg8aD/8htAJV2VTb9M8CoXP/DDAGOrVGrPNj6oTaFEp6+Jd1a+H+uIVOXQw4NMTw
         rzq3iYNdV9yFnFI1OV9oSbZAlUFJCSDnQk5wOuuSFLwGkjrGGeGBhyDmCFlgQWZ7ouYK
         3R1QFyGtQ4JfLnZGMQhwXAEGEK8HL3El4DECIafWoZVVs7hFOHeHR/diwL0/hsLNg5kf
         bjpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6wCUupNyOLfR19Ukqpo0e1qHyCZAAR63B3qGFm1GBjY=;
        b=PIi0iDNNb0mz5HbRe7/08PZ7sDgITZ3aqSmIThMTso2I1vU7NiMbnWXBr/rm8u9WoH
         UKdTlyUkjp6uzcmt2pMDSZZnP8t52xMvxP8ymsQhJy6SVFQcd5ga7yrAdDWh2+C24O12
         2BK0yNakQcZXObqkroraYJfMfVLr6E5gSCzyfEEipjTK3MnccJEj0BEzZYkmimg3oAWN
         vH4fbRXL2ImdxyDN6tm0Kv0xb3J3yZNMGpgGg44RYJGWKOytDQ4uEUguXzP54z56PA33
         onFQ+RZivrQXxCUPMPhdk5t74dnSExXikj0ihLlz0OYNpTrMa/0NIc3vLVSL4EYwqrFN
         ArEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cphS1i1vnAr1Ijx0gIVVbLqM1T3urh2qOncCdECAkYu9vIXHo
	gJTqlNd0Ld0vE9uVbjgRLhc=
X-Google-Smtp-Source: ABdhPJw6lJPOUj3dK8nmH6SWMeiOAUw8ptpDmKvsKRv1WcJV/d7aDN/EAhspOTUASq9UiDLIsna9FA==
X-Received: by 2002:a05:6a00:1595:b0:50e:a7c9:fc25 with SMTP id u21-20020a056a00159500b0050ea7c9fc25mr21609820pfk.51.1652203427337;
        Tue, 10 May 2022 10:23:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5a81:b0:1dc:e81d:6bb1 with SMTP id
 n1-20020a17090a5a8100b001dce81d6bb1ls2431958pji.0.gmail; Tue, 10 May 2022
 10:23:46 -0700 (PDT)
X-Received: by 2002:a17:902:ccc9:b0:15b:c265:b7a0 with SMTP id z9-20020a170902ccc900b0015bc265b7a0mr21474658ple.107.1652203426764;
        Tue, 10 May 2022 10:23:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652203426; cv=none;
        d=google.com; s=arc-20160816;
        b=NiGuM11b8drz2vrL1pWfVmt2woTpbMKT/Bghz835yNh9OajexpfhhOQ34KMRJvuHEK
         t6CMCKYdmIoyeKtw9to/9RHZoFzcB2yWMULE89rZv1z2Zf2+P0pZ2OY4pj7gkqgwcUmi
         6JfIxHtIcyhFWyXGLpdM06rFLvpiIXMq9Brm4ar3gqLYrSnArzR1nuGYP2AAxG3utnmj
         S2dZ2VYJzWAsMMc5GEdD0RjOWFzXzhOyXrTAEshvxiWbBK8Pq69UHabyP0SeCMejsrti
         /SRi1CgOEc7Pz156pin6A91iEHoFcyDN7aPHmHiaKOFM9x0h3YErBuKIXCEqLaJGiz9+
         vh6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t2FaoOCAjCjGV80yLIIB5iRl7eAw6edvFtyAZUcH88E=;
        b=pD34zO50wmcmv+HCMu/wUDyPsJ5A4JFkpTkvHMrc+oY6z/OjJXGAPZN0jNkOw8GSGH
         bMuO7fgYSkulcZAs78TgQ2Xb4dQJ6fPuz3f+sELdFJlQ2zzUBUfNAmU/x0iWKJEsRq+x
         idlsfzT01qikfuAf20nRlGPJIbkGMC5w8BQoFvUWZPk95GIdcifWHbHenyf53OBp4n/I
         yb4vUQbhI/hhy7wdhFomOkkl9K1Rnue4FM3eejXF9hiwIw1n4ONYCrnAzxMlRdP4CTiH
         8WFIzB36rRNg6pUyw5WpsvU7Xf/2aVnPLsK9A1uuLFIpHCiFTSz1FuAG26q+WuvEYnem
         mNXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QRrlfvMd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id nl14-20020a17090b384e00b001dcf3849e50si313372pjb.3.2022.05.10.10.23.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 May 2022 10:23:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id h85so19229612iof.12
        for <kasan-dev@googlegroups.com>; Tue, 10 May 2022 10:23:46 -0700 (PDT)
X-Received: by 2002:a6b:8b17:0:b0:657:c836:de6 with SMTP id
 n23-20020a6b8b17000000b00657c8360de6mr9354382iod.99.1652203426566; Tue, 10
 May 2022 10:23:46 -0700 (PDT)
MIME-Version: 1.0
References: <896b2d914d6b50d677fd7b38f76967cc705c01ba.1652203271.git.andreyknvl@google.com>
In-Reply-To: <896b2d914d6b50d677fd7b38f76967cc705c01ba.1652203271.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 10 May 2022 19:23:35 +0200
Message-ID: <CA+fCnZdZm3ATDj-nGs+6RNnKFtq9+0Zi3yLkaxv4Q9SsUoy7yA@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] kasan: update documentation
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=QRrlfvMd;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, May 10, 2022 at 7:21 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Do assorted clean-ups and improvements to KASAN documentation, including:
>
> - Describe each mode in a dedicated paragraph.
> - Split out a Support section that describes in details which compilers,
>   architectures and memory types each mode requires/supports.
> - Capitalize the first letter in the names of each KASAN mode.
>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---

Forgot to mention the v1->v2 change: I reworded the last paragraph as
Marco suggested. The other patches were not changed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdZm3ATDj-nGs%2B6RNnKFtq9%2B0Zi3yLkaxv4Q9SsUoy7yA%40mail.gmail.com.
