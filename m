Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLXQ2SZQMGQE3APZQKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 55C4E911E86
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 10:22:08 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-dfeac23fe6esf3320481276.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 01:22:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718958127; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q02QxJKH2+3BSwv6UC8j/nSX+Jyt4qC0HAbZGNJwPoRgPCRuCSvPQViaRGH3qtMA3x
         C267MY4XOZGAAias3eK+LrOv2PdUBCliEf+qSvAsOdcH+/sntJJVQz+MBwStjAidjvgr
         viTkSXsvl1GTuVY04j665qVTj/i/lzqYVDk80fQxMUnsT5xUGbEHVz7QA/zZCCPjVmtX
         wzfl0Oi0sxEVCmOnjcTxIMFDo7p/5lEvnwqHg5ApsJMOndJcSbBJzjImNkMtuiRv/BNz
         Hg968ceNjywAQXSSbHu6zsNP5vzkHIKx8WegIzVlR9KfwPAkXsDKkgqtQIM5TnJo8DYF
         BtMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kHceDKf5HZtpw1F9iLTRJdPuXlnjWIF2rNBdKzUON2o=;
        fh=XVecZsFNQVJ1O7WR37ZhkTD7RqZDRnV4E8UqZjndVn8=;
        b=CUCaF7kiR8y/59FMFSnQvkFGXHBPTXGXulCZjaOCVBClIVYrN3NnB7v1bva5dLeUxl
         IU4m/4gptaQdEPNuX2e5JWdTwoOl7Itca5g64X1QqlcqB1b8yBzXcFWu7mYdnL/+Jon2
         1unPOsC+SNL8LfAVI6yBsSzZYDovMEjVoOepzTDS0Ur2aZI1oJmgGo7F+nuoJtHvfojl
         iJJ6Z38sM+kPwcH4YGFahSV8MkjY2cDB/Qvk5EJ4srrh9/L4t9/VYjVGPaWl1JOoKfTT
         4lxlkmDuQzzOE6flgMIX/RP4pGOMM4oQbBGl5uuhYsl1T/pk2fWKJ/i5NRvivy5Xm+3z
         HWQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mBSUAyp7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718958127; x=1719562927; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kHceDKf5HZtpw1F9iLTRJdPuXlnjWIF2rNBdKzUON2o=;
        b=nQDVrVE5iVeZqFXuKMwxghszOPibu59vT9yzOqdg3n0c8oyH4XmM+pxXqfOCxX8mqQ
         RK3DxNlttq4lQ0oy+Hj/tc+MV2ufr+vgWIr7mmfNmzL1pKONtjR/fhXejDJVmJcHClQz
         VN3aL3OXdUFaQHKqCUvOdLPExJ1Mc0TQlYpbATc5JyfCR1PyO7fXwC3gp2ruVkcuNYiM
         SrIZhxVAh7BnBqgbWnglyVVG8BY3ZFkTtKAzJyLxVwlQVAlHwyx7GvUyJ8GQDPbTlsfm
         mkOqS8cW81Q8PwFy8uItquzHzQkCUcV5z7vborCkHw/ZzI1TOD1CdZbEOFEZOvIXV8Ym
         nyrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718958127; x=1719562927;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kHceDKf5HZtpw1F9iLTRJdPuXlnjWIF2rNBdKzUON2o=;
        b=DLtDlCJKuJmGAGTMsc7CIcFD8FCy5OpamjPRcjADAKuWjICXjzzPubIIGei159nFvK
         5NOtnaEs7QGfG7Z8/3ghxc1JvYbNyEj3EEN0ayeECGttBiMH4vPJEFNnH9MePEH4g7X5
         fr8Ue85T5rHxbo5W+vAZqFlgzMkWp4xg2cvRqDPIqfHywhQlkTKwD9yyLh2273bqF+jh
         sxvkPmxPnsvWrriKWKoRg0ETUCY+bx32staFxO+7pdi+FKOMvmVNyoxyGlDelmdtjMS8
         WmXSu1pWeFfU9xx4xLsVhKkH9UCQSbfNeVJSO7tAy/JO6tfN6HBmRMo2cqtbOKaWZovJ
         sJSQ==
X-Forwarded-Encrypted: i=2; AJvYcCXGfPuXEJhw9dKebXS0msFOjcSLQ/wLQZ/c2w7t2cH/WteRw2yt6Otb5BugMoWvuKX0P5jSErHBj0ZKQ8aQAaG7yCT5WZm1ng==
X-Gm-Message-State: AOJu0YwzEyu07IxRtRNz3H/jXhed9prG6wiImU1s2KRHuynZvELnaqD2
	LG7FI2NoeiwYcBvwi3k+Ff/jYIASbCoqTbl/sDwNPAAOT0Mtwr4f
X-Google-Smtp-Source: AGHT+IHG+av9Rf6VeuW8pn+DqhGHw3HdrnRA7rTSqQWGLJx80lXBvYCRFUNOfDMjjhkFELuVWTrW1w==
X-Received: by 2002:a25:2f4e:0:b0:dfb:b53:aaf3 with SMTP id 3f1490d57ef6-e02be230b67mr7179630276.64.1718958126890;
        Fri, 21 Jun 2024 01:22:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1895:b0:dff:34c9:92f8 with SMTP id
 3f1490d57ef6-e02d0ac0766ls2704006276.0.-pod-prod-05-us; Fri, 21 Jun 2024
 01:22:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWIOggM0tslbgfd1arC8gWTAj8yKDa/CWOqTrGwrFp7FLR1my+38kL3QFRRFDFoJKyC7Pu5nn9YxwA31INU/WK3/58lH1B+B/P4HQ==
X-Received: by 2002:a81:84c6:0:b0:62f:aaaa:187a with SMTP id 00721157ae682-63a8db1040bmr77816787b3.14.1718958126148;
        Fri, 21 Jun 2024 01:22:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718958126; cv=none;
        d=google.com; s=arc-20160816;
        b=HcNncv4NOzSJ0WKfbvoQV9MHfZRO2oIt8vCAoZ3ZGjS7a4Wsff5eavsQbS202cWB9Y
         1x8BLBZalIrpQwCOXpHniJZtgwDxpTOYndjh+vw0kUvwb3egIssDKJy/fgaREqiHB53x
         kIKFobtdgFPXbZA9pewJr+hldpLY4wBMVa+VASdRBzFXsc5UQayMnB2gtokCFALpwj46
         D/oeAzckBvN8eKqsRJeJ0KHNhqtqnJynHhCRk+MBvMUVG6myVRX+Mi6Xn0Ruuidu7Hi9
         1TiMPiCwXQV2RpXEHX3mPlbx1mpYcvNqaP8y7mIr+Z3DH9vctQt/kSn+WVors2D/HTbR
         ifvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=GiWp0R3m1O2e8FqlZeCTxBARLk8raP5XQEmY3Orplv4=;
        fh=HoNoXuD87bomT40n05hUvtpoBPQkBrs7QDi73YbTGAM=;
        b=VkGBVe7JomwyEHi7hKJW249HjGPlkd3m4udMcL9eMEtvTwa4rdYkM1s0sE++kJIaea
         596fQeh44ONtd+2jpRsXT7jOLzWGWD+yrp65pk4sZWQU78I3F66209G4LI54/Gjsg+iu
         kc5vA1QJ1UEXrz59rO59nqXSeOznsxsx8CsCSpQzqI8Lm3O7bD7ZZES7quudsoNrWKW0
         WMDb4nRs8FmCa2KNAfXiIqCKkFAa/CHUjs6naNhfI9+KExtJsrKt6aNzSDrRxxTrWRHu
         Gu2vMOqyceh4Vl/eaWurSDl8fDHbG7DwPGe8fCNHNMFQeoxnjNxPvnyCqJqleNRCgwIQ
         BSgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mBSUAyp7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-63f0bde297esi764207b3.0.2024.06.21.01.22.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Jun 2024 01:22:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id af79cd13be357-7955dfce860so115083485a.2
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2024 01:22:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXNQYbfP+i5V8okKsYci/PSyebKVyRMWtWPXHSEDrv6whrtYT9401iSnHJMuudmFDDe/T3e0XwNodJv/ieGxl71MG9kNOwok8rG1Q==
X-Received: by 2002:ad4:5842:0:b0:6b4:fe1a:9ea9 with SMTP id
 6a1803df08f44-6b501df8ce0mr76732636d6.6.1718958125525; Fri, 21 Jun 2024
 01:22:05 -0700 (PDT)
MIME-Version: 1.0
References: <20240621002616.40684-1-iii@linux.ibm.com> <20240621002616.40684-17-iii@linux.ibm.com>
In-Reply-To: <20240621002616.40684-17-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Jun 2024 10:21:29 +0200
Message-ID: <CAG_fn=XKAdJ_VR8_fsOFSRqZxqGRB+GsHMMQjuy4gQGEGi9aDQ@mail.gmail.com>
Subject: Re: [PATCH v6 16/39] kmsan: Expose KMSAN_WARN_ON()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mBSUAyp7;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Jun 21, 2024 at 2:26=E2=80=AFAM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> KMSAN_WARN_ON() is required for implementing s390-specific KMSAN
> functions, but right now it's available only to the KMSAN internal
> functions. Expose it to subsystems through <linux/kmsan.h>.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXKAdJ_VR8_fsOFSRqZxqGRB%2BGsHMMQjuy4gQGEGi9aDQ%40mail.gm=
ail.com.
