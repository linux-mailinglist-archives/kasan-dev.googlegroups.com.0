Return-Path: <kasan-dev+bncBCCMH5WKTMGRBC6TY2ZQMGQESIMAY4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9736990D776
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 17:36:44 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-37492fe22cdsf49313155ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 08:36:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718725003; cv=pass;
        d=google.com; s=arc-20160816;
        b=haz4pMD6c27vcnOvklRGWrhUYBdILNpLQ0LXnplWYI9zrrZkV+plIIFJ6quphYser7
         Lj9IuXjT7Z8kSYcQuUjUYEeN0VEiPU4xtpO5y4RpqQfik56e2i3Ra0n1ewGNcrPL87ba
         rZ14eN0X0TuOEumB+gU/GF8BdzUH+0oPlYfTIwx8e/+xkDVkogc8wS3pnrlYyPiGjKwU
         3+L0zNrVONBUzzuApHxe0YtOB/NRme9BsVit4DwP/jzuskzkLsjO1T8kav5Hj2/HRoN2
         wFbwnquSdsZZhgfKZ+058f7mrrPYaf6uZo7yFYYKd10T8khKJ3Ymu/RZF1Dh7db4BHas
         jbSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xkXRWmIZZhFH1JJjmXlcYRUGPzOvBlXv7kkNANr6mO0=;
        fh=Z4mtt3nev7SOAIBdY/qWz2CaZ9C6FryYl10uqR353zk=;
        b=vWmAxHCilFX9TsxIjCR/4OK5LE2IzQHL1r7yH5VnXiWZnOosBedRrX49zWSLDXrQiQ
         crwdSzgvdLVmDufbB6dJxC4MTn6X679wrVyK+EMOfEs8ppjjQHpQtMLw8NVXNcfyhaVN
         Jje7rgzm8hq+kcjCmmeBxEKPmHGcCdk0Lv3Gp9yf15szm38ob0eYGeaYoARMiblGz9VT
         W47HOr95X29U/+pyXLq0YPwzyI0NEEuzDRx1i/LrpYcE047PbLYVH5iArR0BAlicPXm0
         fVy3fn98YLu3NXCH/R6LGpPyhzS2BBXux3InGhMTOHp1YC7Ap5l1o2YcawhxTQNdCwPz
         yAHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wi9xFtYp;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718725003; x=1719329803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xkXRWmIZZhFH1JJjmXlcYRUGPzOvBlXv7kkNANr6mO0=;
        b=CDWEay5tHCIZySl8o2JQFe1eHu6MN2xgroqM4ZoKitn3UuuNgwOiGWm7zRxXgGzixB
         bXkwIGQFMNHIWDUsnzxjDzo/AMN95oemvmGRTwL1GrIxQwFUqfHQRBO8ailhRk9mWPmb
         bLGZkMcKem6Gq1mbrCbR8zZHh6E/3sJp5e57Ul4n8wKBGuYk3addZR0aYdGj7BjYPnIW
         4s7D8Mzqfe7vdJObGfD5rUp7qTwwP5n3V4CITKlrgsNwimMtsVuUJiw4FXeX6UXCTgiv
         7WzurthSqEsUDQGURma2nbYL0hzECuRbA55JDDJaiaw6zxkhthp1bhSm+LgDhMUU5TQT
         wb+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718725003; x=1719329803;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xkXRWmIZZhFH1JJjmXlcYRUGPzOvBlXv7kkNANr6mO0=;
        b=LSTCaieKKGxxIjFgEe4dbLS1Pa1GMp2ltyzVO2JHdHZhoaVHGQsJeDM5DqnARTQOg1
         7fyVlulQXlg4nezGT2pXlETfu8sgDXc2lhUpdSFqtHmzGQeidymjFKb9Uu4ID+A7aFKc
         Ro9dXxzVlegokDjGfGqtapBbpHqmeXNobScmQDZOPFpGP6DcR2s8arcO/KN3pcrMc3yn
         C5cjRKVPjFN9aR1tuqwp3muoXlnKyJr0+Qd4txh5oWvnCFU3Fbuakebc+nm7nVSN6jvc
         vwmAxP/mNT0C86mOvWe7RCnTKWDs2KDXrOUk2m5BSejr4U3EV3d1dl5SxfurroLlbUTg
         2VDA==
X-Forwarded-Encrypted: i=2; AJvYcCWXm7+u4xRFWKlUfVcqnNugNezxSXJNVXBfCVKOHujrtoiuB71y5G0r6aDs4QGra0JpntHdlPbqbLhNE+UzkxkXSWyBhaaseg==
X-Gm-Message-State: AOJu0YzbLRppO5uTnCkZib7hZY83lXv2BFnbXyCAkP0Uf1Arae8yD4Rf
	LX2CtGsAhq1vOueHfvp3yZBBMiTq2OdII+mqLaDsPVYlF5Niyuz4
X-Google-Smtp-Source: AGHT+IGP1q9TwbqhrEQjalbKZAqg4foNMZLPd5IO1gIyzcRmOye9EA40HojiYvvKvZbloxYmCkK9Ww==
X-Received: by 2002:a92:c265:0:b0:375:b21f:9ac1 with SMTP id e9e14a558f8ab-3761d11c162mr1290855ab.12.1718725003312;
        Tue, 18 Jun 2024 08:36:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3a09:b0:375:cf99:f713 with SMTP id
 e9e14a558f8ab-375d55821bdls29057015ab.0.-pod-prod-00-us; Tue, 18 Jun 2024
 08:36:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV1UUBhy+8nbcRPeCLaJlrExGnFTeQy1/8nGypQ6txEq3rVEudMXnI7pULO2wQvy4JE4Ds9nHUcnyzzvthjE2w4PJgz4UF3SOa4+g==
X-Received: by 2002:a6b:913:0:b0:7eb:84c4:3673 with SMTP id ca18e2360f4ac-7f132643e36mr171910739f.4.1718725002390;
        Tue, 18 Jun 2024 08:36:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718725002; cv=none;
        d=google.com; s=arc-20160816;
        b=1C4qgbqTP8J84XnlpPdEoK8erjmXx0SZO6pLsQUk1FnWrHqTNK6k+dwfhVCyptfK/m
         YtV1WiET4m/NHQwnJ99FpgdcAgz6/gmF1Nf+90ilzZQfrB7zjKlToBmLZ/0K6sdPkj3z
         quRmuXhPKxLPmRrrmOvEuPQsTMawn45mwNIehANB4SdsTxFs4PIEDDWAQicxyP5USCJb
         nGxgDYxTDcFtBY7bhcSdxj8B/MybT5FaYnsCp8/DDL9POWCIXQ5NdOgb9aPWjbCMP7GW
         qRorWrg9vNZ0DpkdaGu9zGo9zpdnK54VkM03GvXmcCqlle9qMvV7Fqk1YqrEHKIDgfQ9
         7H1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MEWdl0tqnkjxn0t/wprGhWa8mDGC5ARyeWTuu4/vhE4=;
        fh=bfXmEkvYhZA3uwA5Kkj47kO4J+VgmbMqxvV/2NidQo8=;
        b=tB9kE6p4JIO8Jtt1/uRrUaYi6WhOhSAe/WNLPdA0E2F6O87nKbsSd6re9hAJFrWZzT
         49kBNnmSo5FeCXcVzjYOHldDQUuqmtZxuZzjNd5KHI9wEIKy1rkxg+I0AzUqWq5/yGK+
         c0LSxofPVuvAw8UK+9d5ZYNACYplthij7OaMHOW+R75xITIPlNQn+Xd3AqPgEPAQ4bbv
         TJ5qc/5YIvLGpKTG0uP9DwXwlVuMULtYaxwxB44EZBD7KjBX5bb/eGxTVJ8UUne96uxa
         5bLY8GjHKDrQaTrCxreX9+D8TQXPS+8+l8K34v7SxSxVXVx/xE654QxjWk7HwJN6cx9h
         0YPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wi9xFtYp;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9568bb7a7si531510173.2.2024.06.18.08.36.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 08:36:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-6b4ffc2a7abso2676676d6.1
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 08:36:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWGoctuHptW2glqptEHcG+q7obr6XjJq1rBTa1oJJNsyMu3jaHmM8nv2vGwtAGcr5WMdYLg3JRPArWsYLqGLmQlRGS2vXllG4wXcA==
X-Received: by 2002:a05:6214:e66:b0:6b0:7d88:c307 with SMTP id
 6a1803df08f44-6b2e249503cmr44454876d6.29.1718725001515; Tue, 18 Jun 2024
 08:36:41 -0700 (PDT)
MIME-Version: 1.0
References: <20240613153924.961511-1-iii@linux.ibm.com> <20240613153924.961511-36-iii@linux.ibm.com>
In-Reply-To: <20240613153924.961511-36-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jun 2024 17:36:05 +0200
Message-ID: <CAG_fn=XczonMkhozFo9YT0pJhPPzfjiAMKmHvVBb9QJ6_mcspg@mail.gmail.com>
Subject: Re: [PATCH v4 35/35] kmsan: Enable on s390
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
 header.i=@google.com header.s=20230601 header.b=Wi9xFtYp;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
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

On Thu, Jun 13, 2024 at 5:40=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Now that everything else is in place, enable KMSAN in Kconfig.
>
> Acked-by: Heiko Carstens <hca@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXczonMkhozFo9YT0pJhPPzfjiAMKmHvVBb9QJ6_mcspg%40mail.gmai=
l.com.
