Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLP5TXCAMGQEYS5URCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 696F3B13BB0
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 15:44:15 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3b782c29be3sf1299885f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 06:44:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753710255; cv=pass;
        d=google.com; s=arc-20240605;
        b=BXiAsZjIi6PY+QctcHl062rl4X5sGd1UB++7qjqr8Reo46qdceBQzcz/2x4UmPhSow
         PmpwnfJ0gmCza54MRGzwdx2sRaQB/O978Tw6KpXOnruk28UX49YoA+684P4cqSdlLIWt
         8OOpfe7+yT4qrs+u2KtEPZQu8kUEBAEn0tk/+wF/TYKLK6hl7gjJo4GtDPOQEdGb3u2C
         wPiFJfDjww1GLq3AHbv7PEdrN5HU3DOvdRpLhle3IFsq094c4eGl/65UE7dKw3/T/507
         ihkCgMOsx8Zc43YHuA4tGXNEGsJ1hODu+95PK8ryQnV+bDayxqSt7cgHFwQT669EQfNu
         Op1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=mYWqRgRDXOUffCMUB4nBfHT9k0SMs64Cu4zqWA7i73Y=;
        fh=CPjyayb2mB4Fgt5jHySZsV+CxdDDfwabucCfrVMQiMY=;
        b=kG8aDqdVrezhnw8xRocGSYGwm3PXSRVJwko8x+Rp62BgchsTxEn9lPeUUGK0ZuCbVq
         7t202poDxcuID2+pO0JXIqy4vdv/+11qGSNYljEBvBD3DTe6XqjRzeF0aA0//9G9iez2
         pnULER3PaYGsT5xGQDmDak5nd7WmPAZfXL/GNKkX9bjqRJstT4xvZ6PwB7e383EQ2Bh5
         jAUwUBKhtcrnAdWHOD84sUOvq+tu6iQOZO0REr42rvELSvDVI3/79hUIyMlwm/QRJuko
         qOnMsNVkN0zRocgrfTqGXB9+L0jz68ZWxh8BytqseSXhaSNPeFfEIZO0+K/w+vu4Q4rP
         LE9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nZ8dVNj+;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753710255; x=1754315055; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mYWqRgRDXOUffCMUB4nBfHT9k0SMs64Cu4zqWA7i73Y=;
        b=tQkZTzo/nHVpkia1Qs8TeJGCBdrZFVJLC/r69hNGiv9R63IrVFe7m2i5AB+B4YnRnO
         wo7aUoyLUj0Phz+rD7rgqZKxjg8DCNpyCHEcwvUIo12F91+esf/tzg8GiUY+uGeXABUU
         hueARG3tl9B+nFVTucM9rOSVyI/W3IATCXFrwLf7W1SA3DgX3XS7XPIUZtgNBG1qrg+X
         9U6HDNCs4vGYUAidWbWRQ66Onv8PcuWkWREBBvg1YFz53IlJOeeyhlYcpZEGHOrfwsWQ
         Jtk6hFu5O8JGZD153h9kYa6/IuPa81YKe1a5t+QkV0u6fnV1ynIgI0YHTCq9MXf2wZvg
         S68w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753710255; x=1754315055;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mYWqRgRDXOUffCMUB4nBfHT9k0SMs64Cu4zqWA7i73Y=;
        b=aYwaMKz+2rxi1J3UNZzMedqadvRO2KeMergqYY4wg2jgYr5UCXMXFCMbO55kmIZqUP
         OACTJUzEvP2YUY+dIv+gOEwhlye6HQ5G1TunJcmqqZhi1HOqNdqNNFv17ofvrBoXN32S
         yVDC2Zf5q43YEVmdMw+66THFHna1foUxbXLo9h2GZjvZYn/ceHsYKKw6rHLA4D+ADBTp
         sYbw0Sx2k28XdDyTeRIizRyFSXizp0uGFXEIP3lRYTrF+ARqZLoyQSGelD/d4HUEyMpO
         iEexuwGgCZ+rDd1my7wL/K2SS7MMEbgN1cMuSlYNAVPUwxq+imBFhoeq5UPZW34iw91G
         qfLA==
X-Forwarded-Encrypted: i=2; AJvYcCXYrOQfskM1YZPCEwYRRJQEnXhW0WEaMnVP+OkfiHeBkT25JnGJLTxiwZAtRfYHYJHVB9EX6w==@lfdr.de
X-Gm-Message-State: AOJu0YxKzth7Eo7uBBYdV88eSjjcLm6PcLbbDLU4/PB3L/8jwr4k20lq
	j/3eCcktHFKKZlcTRsM08fSrLz9Jlv7rWOSR60d5yRiW/Bi7+rmGU7E6
X-Google-Smtp-Source: AGHT+IEJSrqecmUddSwE7OjJL8cf2gvm9AC4d2w5r831rm7b3hHrJPOc2p7upyU3/mSGS/5YkrFxfg==
X-Received: by 2002:a05:6000:4212:b0:3b7:8af8:b91d with SMTP id ffacd0b85a97d-3b78af8beefmr1751440f8f.35.1753710254500;
        Mon, 28 Jul 2025 06:44:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZedX/XeG6mpL6xjlbOb7kvhzIWgCmiN0Fz2upydMAUlag==
Received: by 2002:a05:6000:402c:b0:3a4:c906:f8eb with SMTP id
 ffacd0b85a97d-3b78a132caals389022f8f.1.-pod-prod-05-eu; Mon, 28 Jul 2025
 06:44:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbbZPk2NDQ4m1Q22mQruVXk1TgujSjBFTOC5kWG17KTiKBjtRnaSuNAuEbZ3W3wtzhGacueYvUcZ4=@googlegroups.com
X-Received: by 2002:a5d:49ca:0:b0:3b7:859d:d62b with SMTP id ffacd0b85a97d-3b7859dd85fmr2644558f8f.8.1753710251220;
        Mon, 28 Jul 2025 06:44:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753710251; cv=none;
        d=google.com; s=arc-20240605;
        b=TywMneM7XBIqPoSlIQfiY2N044uHlS65gxo9dZaZqEEwDV6TpP6N1kLYWPc+GMl6Fi
         gxFV99QUKraO9nh4Jm3qXcc4ZIX4t/Q38ebUi1ic8zAODPcoMHKTWD9Lh4PsRfxWeQCd
         MjZcu+uXT2GqqwZ654n0MeEx7nGmLt0ZqyXOh5mAFJWivZpx2MbLZ67l0WMlp2+14dvA
         JuSsXr12bFPzbmPU1h1PI8FzyAzrjaKPUgnikUL39pP/V7FlEBWdH4GE26tmOkJ6hwhQ
         72mGoOxkIfB3aU9P4K6ax6roPgwvxksn9axN3GyVIUtISC4rxG970tOdUVeOVSm+eLVz
         5xsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MrIeEid5T15sP2bmZ2K6W0oyz6k1/QdANuHbM57Jiz4=;
        fh=pRYJHT46+1p4VzUehgSzZLJX0DGIEbzEVjMqpS9hb70=;
        b=jG2Ha8ZwSeCLc++lQAEtWuIvfVK0Naxj6C+Sanstq+GHDl8TTnGHUZU7pmocYN2ZJl
         7AO3WLU+xSuoGnTXVEIG15dlCM2kn4c8ekDyZJVu/Z8YiJjWLNa2u7/zJ3MRfkAYNdFE
         ea63Wcdtas9nN4pWea+EfWeHd2jbCLgG9kaV8zGh+UEJm5SgCM10HTHq53wUyvaEy1su
         jHpXRi3GknQ4+P/quwqlVIzW6llopgV0EkctViKkLRXqc4wIOWsGZ4gwjayQ3aCJNp1e
         yNdmljcBSCt1o9CygMgwA0R64/yd18GoU+4a+ETo2IXrv2PyPX3189AN4lK/DZEQMzYV
         8vyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nZ8dVNj+;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b778edb62asi174683f8f.3.2025.07.28.06.44.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 06:44:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-454f428038eso39272935e9.2
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 06:44:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUkdy098L64LjKQOgV622O59P4jm5uxEkx1B+mOmOTtT+Ey9tpiy7cJwz0LEPHOqC5c0OHtm38vvhc=@googlegroups.com
X-Gm-Gg: ASbGncs1XA7+7O7BcKCPWRcyCR3jZgxFHoF1fTzB/eHSOhnCm9t7B5BWvFcuVl5vgHl
	5mQ32DBXlofA0KfaSWBIWyCjiALLl/rtg8n2+OxIenz5r63HbFcwUfcka0LF0HlMRxoB9PGWXdF
	lEmff8AXPSEX11Q+/fLgW8Z1xNfFqK7c0CjFYV2c5KVjAfYt6tcUzqnOl8xT5e+9ZiGO+mj7jk+
	QosNsNuFJ9OtMUeSJXiMa5EuykUVuXUkV/xQHvwEaP5OJdMBVggkNXn6x/ruWwpQChOT2m9Tu7w
	0d5JQiuCczWtvstopTDcxXVEMxfVNnciB4hvTwOO71CNJk6q3y9KDveXthv3YDPQ93R8P1Z0mJK
	xlRkDluDMHuiYoSmHY2IpsGPReXxLkn8HwtI1SaMaLiddZfFEn/x0uRk/lRc=
X-Received: by 2002:a05:600c:1992:b0:455:fc16:9eb3 with SMTP id 5b1f17b1804b1-45876656c6fmr81389815e9.33.1753710250471;
        Mon, 28 Jul 2025 06:44:10 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:2834:9:4524:5552:e4f3:8548])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-458705e39b1sm152270025e9.34.2025.07.28.06.44.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Jul 2025 06:44:09 -0700 (PDT)
Date: Mon, 28 Jul 2025 15:44:03 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [GIT PULL] KCSAN updates for v6.17
Message-ID: <aId-o3ijDLf38vtc@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nZ8dVNj+;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Linus,

Please pull the below KCSAN updates for v6.17-rc1.

Many thanks,
-- Marco

------ >8 ------

The following changes since commit 89be9a83ccf1f88522317ce02f854f30d6115c41:

  Linux 6.16-rc7 (2025-07-20 15:18:33 -0700)

are available in the Git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git tags/kcsan-20250728-v6.17-rc1

for you to fetch changes up to 9872916ad1a1a5e7d089e05166c85dbd65e5b0e8:

  kcsan: test: Initialize dummy variable (2025-07-23 08:51:32 +0200)

----------------------------------------------------------------
Kernel Concurrency Sanitizer (KCSAN) updates for v6.17

- A single fix to silence an uninitialized variable warning

This change has had a few days of linux-next exposure.

----------------------------------------------------------------
Marco Elver (1):
      kcsan: test: Initialize dummy variable

 kernel/kcsan/kcsan_test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aId-o3ijDLf38vtc%40elver.google.com.
