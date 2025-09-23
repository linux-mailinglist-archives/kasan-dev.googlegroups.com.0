Return-Path: <kasan-dev+bncBDXZ5J7IUEIBBIORZPDAMGQEZDB7DWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id DA586B97363
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 20:36:19 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-43f2ad09922sf492486b6e.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 11:36:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758652578; cv=pass;
        d=google.com; s=arc-20240605;
        b=HDupRCG5fqEAkVjoFOH7D3pZJnWcUo1/dxWmAJxEJpvRnVfu1mBPsrXZmvA3RAEaEa
         i5qgsQiCuGfUSWoA2I3xxVI5hDrvj1P9qXYV0oOZ4XrdxqwaBBPJgx9nTplk1b0x66uy
         +Q0+VFIz5yl4WPhy9azRT/8sR6obzFSvlBOPPvI4lv3gAi/ZaUZodxVM+szxHupswGG1
         mmyhTGd5eSdBbXKDLE5r4oBwCAliHCxNXCDahydBUcxLllC37lf5U4nbJcg/Al6BVaw9
         FreMheYScFTaThGhpwY3xAF0qNJO7NjDiTDtYYbZwz7KhYHBpEjD0RZTvMQowPD9pd4g
         +aPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:subject:from:to
         :content-language:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=EHIrCILYBb0dJ1iuzk8i+J4EeqaXA3S4JXP/eAou+VM=;
        fh=YVItQk57TohfRGiNm1LMrlPIqMMPrH+whGhs1QApFCA=;
        b=lNwTnuWhjHSgoC7U5RAZi8j/00fgZtO2Rbb1uI0UMLn8nej9i2z9QXKAFKz1YLZzIO
         SEmeZuXMVzA57GU3nfevNrzpYwdyVddCRiZ1DJNedCpNxz1dK1js7ceD4j1aUXFkf6v0
         Wj9TlUc5TCUzZmhiOK33xz6sWXlgKzNkFyXJegvIQy/oQjDJl8dzQk8ROOnFpx2l85Ij
         rBFgrxGFAUbzSGI5FuqvrDVoqb+kYCyZI4DhitZM48FoYkarnN2Kdy+lPuAh+vaNT++z
         L85fJ+LKCXHShB//2B+lcAzuHQCPEOJZOE4LSCiA7jE6P35rBJ0fyMvK9L0O6WOgN7Yq
         tOBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.215.178 as permitted sender) smtp.mailfrom=yskelg@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758652578; x=1759257378; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:subject:from:to:content-language
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=EHIrCILYBb0dJ1iuzk8i+J4EeqaXA3S4JXP/eAou+VM=;
        b=lDggAC68qbYvzXV6cFGDfHK/NdtpFkq6CuHr2ZryTsf0Ij5wlv/OrfQuScwNPL8v/r
         s4o7hycGma9m9/n0GZxK6bM0RRrcrm1ork9ir9iVfMDoqKnTsPzXR9vSs0oRSxzKzxDc
         LpDYgSKDDQx5IYeGCjv7GJW1R0RwtdQbd+dkaZWpshKNxV3b/1oVelEP/wAWS3o340Z5
         vzPiwbVSF8etNlasYTTxuzblWyGZIEMvce0egmSDW0atA56P3TkiPDkXplQ+GLm/EXav
         5M8BWOwNDk9WjSJKfnT8Fz4g/g93rz00NUb7y6uLBNRTfl9V4cH7ZQuBPaiOp3nYZELP
         duOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758652578; x=1759257378;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :subject:from:to:content-language:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=EHIrCILYBb0dJ1iuzk8i+J4EeqaXA3S4JXP/eAou+VM=;
        b=Zfj9M7/Pkr4dXOPYMb5NtUSoPmmtLz11LQbxO4IAQsz2eUCurA3+dksQ+8/v1AdlkB
         bDzjJ+HY/aq46Fw5MZXl4jj594R3v4+0sgdew/4Hy045kai1WMeN7kkmQIgvEPHqwYc2
         trPx8RX1mghL1QCSsLTCQt6tu4MBdzJlw8yUEbJUrp9cmgXU1IEUcMUHlEo4EWTMicJ5
         MlI9aKTXxVi9oC1LrJYeNBCHMS6LtL7GdOttPXGdrn2gt3KEaK7edPcN3qiYQJkjc+7l
         Z4k0m8XbyT0FaMqZ9qz0gKvEdtj1sjkTdeCbEfWL0l4qIz4Spyq21goe1E5mLhjFduCW
         yzQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfyTYEZi4KNmkUXU3irp6b3BI8UvCh+GQPTsClQPHra/rujgl1dRxHGbxMFkmR6b0ZQzwoOw==@lfdr.de
X-Gm-Message-State: AOJu0Yyxi0pmQ0asYCqA49wcHiONL/Cc7Fv9UI5jUzm4NDwYx3F2WaXL
	RLABDrT8oxFSOXSi9VeiG9Q8ZZhL6YxN5wuBhQy2xpyjmsGnz603K6SE
X-Google-Smtp-Source: AGHT+IGy77DpNM+2UGuvUI1gHIdYsczFx7wsN+gewDFSf15AzvQaCXQld2GNJjBaBBxbbtTKlSD7PQ==
X-Received: by 2002:a05:6808:4441:b0:439:1192:c278 with SMTP id 5614622812f47-43f2d4b1896mr2009234b6e.44.1758652578203;
        Tue, 23 Sep 2025 11:36:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5yph4vVSHhI5n2O78nYFySdWoB4BT0NVgYfEM/aRcMyA==
Received: by 2002:a05:6871:e020:b0:31d:71b5:3ff8 with SMTP id
 586e51a60fabf-336fca6a7eels2437137fac.0.-pod-prod-09-us; Tue, 23 Sep 2025
 11:36:17 -0700 (PDT)
X-Received: by 2002:a05:6871:2112:b0:342:6d27:2dc with SMTP id 586e51a60fabf-34c8aa0e3d8mr1760463fac.48.1758652577143;
        Tue, 23 Sep 2025 11:36:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758652577; cv=none;
        d=google.com; s=arc-20240605;
        b=BFqdnIj3Ea3L/Mhl5fWCvO44CTJXAWeOj+cmkRnwHjs7yJNgc9KTSn9F0O/3cCvtm+
         QA6s+tsESK7n0cn68jUNqDXMPUgyjaP7rg3hA5oP1U2ofROAroQYcg+4g0NI1URtl/cr
         Qwxil4GCw6fd7EMje6UTV24wWdbz5mVTCREcreSVnJcI+PII1m9v9xeGudVWNd8Mzvzr
         FQ47ZuzFv8jYQyUWzM7pCwAmLOpahHXl6lmAySF6v1SgxRqdNzYGgq9Rr7ClVq9ss3PA
         F7EQbOfRPNDjGyn8T5VRZN9dhNCQCcayMmg8yNuAU8ker2k64H3Q+zTRqDWbjjGSdItc
         mG2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:organization:subject:from:to
         :content-language:user-agent:mime-version:date:message-id;
        bh=e3J7d4yai+zi/pBz65x/vQiIH/bRzhI4L6D9zzyv8wI=;
        fh=bCOljM4uiemDrUTf7+Qee3lXcUh1NgppuMpe3uCga+8=;
        b=lKBUuUS8RV3+wwGiClbcS0IwEAye7P6ONNiI7jfOCPO2SkbRyMT/RtuwepA/OHvUNI
         kMk3Jz7/9AScMyT3RVqcSnSaBGPYE9QZ1AJC15RtZF36dnN7C97ZR9ljfLwWLNiI9zB9
         nTQYqgESbZ1SOC/JtmvKQizi05uAmbn5wFLH16eEY5FdwfeNBZ98w4n5bAeFnMTiCwGK
         0ouQVAcUfJzTe8fWZEQ2QZcSimGiW5X0tBKI8o/K+RW+UIagveZy6UJ6OX+4oT/HFHSg
         vlENAHVBLxfDBxXehjOC7i1OkR7irfKXXmi/pjM4AZREsLHRBJ2CNXNUqYM6z00ckLrW
         +aQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.215.178 as permitted sender) smtp.mailfrom=yskelg@gmail.com
Received: from mail-pg1-f178.google.com (mail-pg1-f178.google.com. [209.85.215.178])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-34fc72eeaa2si90469fac.1.2025.09.23.11.36.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Sep 2025 11:36:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of yskelg@gmail.com designates 209.85.215.178 as permitted sender) client-ip=209.85.215.178;
Received: by mail-pg1-f178.google.com with SMTP id 41be03b00d2f7-b47174b335bso931985a12.2
        for <kasan-dev@googlegroups.com>; Tue, 23 Sep 2025 11:36:17 -0700 (PDT)
X-Gm-Gg: ASbGncuwlz0BqX1pPJXybB+inJLyM4V/XgzOYvQTDOJTqVTqwig6g8csf79zr28UbnG
	I0K77hayqNNzXGvLpkyU9M6aQau6fGJ/u+IxTfmqxE1akWIhLTTUy9g9VvhMFeIsC7b3eIvqJoA
	dwp4iIKvMlDQLDqZN5PiHSpZ94v7e+EHN8tWDf/Y9+aYt5d2TmFXaLFghe/wmeHSSxtleeDR+7Z
	9tfT4mV5L7K3B+rQGIvE/tyXK2gBT+wyPYxF4a7bHORLAaGCrbBZs6kZ/xp7rq9ZWGNbIpKVsRt
	W2cycSa4jILE+zUU5G4r4z4p6X+RdKGVqEi7aMACaHBmkUcRvqixkVeiX+G0OqfOh/r1OEKtx7h
	dK/j29vQ1tIL9ITzZicwf1owgWYFJ5XbmyXuETTSskziBd4Lf6TUhJMlGiYo3lMdAFlg1eM5qEa
	hw7/35eJVeX63W0YsKecDzWBB9s8/I
X-Received: by 2002:a17:90b:4a51:b0:330:944e:4814 with SMTP id 98e67ed59e1d1-332a96f8060mr2466215a91.5.1758652575928;
        Tue, 23 Sep 2025 11:36:15 -0700 (PDT)
Received: from [192.168.50.136] ([118.32.98.101])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-330607b22bbsm16620157a91.15.2025.09.23.11.36.14
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Sep 2025 11:36:15 -0700 (PDT)
Message-ID: <a620cbb0-7302-404c-93a3-fb9441431ba3@kzalloc.com>
Date: Wed, 24 Sep 2025 03:36:12 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Content-Language: en-US
To: kasan-dev@googlegroups.com, syzkaller@googlegroups.com
From: Yunseong Kim <ysk@kzalloc.com>
Subject: [INFO] vock: KCOV coverage toolkit using LD_PRELOAD, attachable to
 arbitrary userspace program
Organization: kzalloc
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: yskelg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yskelg@gmail.com designates 209.85.215.178 as
 permitted sender) smtp.mailfrom=yskelg@gmail.com
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

Hi,

a new userspace project named vock (anagram of kcov) [1] is available to
support Linux kernel coverage analysis.

vock (an anagram of kcov) provides a lightweight wrapper that can attach to
arbitrary userspace programs. By using LD_PRELOAD, it collects KCOV coverage
transparently, while KCOV REMOTE coverage is obtained through a dedicated
driver program. After the target command finishes, the collected coverage
is reported directly in the terminal.

Example usage:

  $ vock mkdir mydir
  $ vock smbclient //server/share -c 'put local_filename remote_filename'  

Requirements:
 - The kernel must be built with CONFIG_KCOV and CONFIG_DEBUG_INFO enabled.

A demonstration video is available [2]. vock repository details can be
found at github [1].

[1] https://github.com/kzall0c/vock  
[2] https://youtu.be/QvWtFuQy2r8

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a620cbb0-7302-404c-93a3-fb9441431ba3%40kzalloc.com.
