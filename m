Return-Path: <kasan-dev+bncBAABBXXB2W7AMGQETOQIFFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9163AA62C98
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Mar 2025 13:21:52 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43cec217977sf4123375e9.0
        for <lists+kasan-dev@lfdr.de>; Sat, 15 Mar 2025 05:21:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742041312; cv=pass;
        d=google.com; s=arc-20240605;
        b=iAjSniweuXQDD5q4ARKXIJ07mfrffC2+yy5z6CYEg5FK5VD2OkbF/uyxUKv98f+zpJ
         4jUAdEbJV9V0Rt1YZau1973OfQj8Gw8NX68Ww7m5cwrcD6bFAJblxGH9wx9BZUF5GwB3
         bpOwtWTHuoeVnvh0HdV/MZHZUZvzzjCdgBR/6Wu4IzEJAv+WstNxtbxdtxGF8SKysRqf
         lIfq0spWo3x5d/w/D6RQOURxJu+G68kW9sjFzPfM3E+hrf/1/i5bw5IadMUeSrqzDn45
         vTnFnXLTbTtGGhHJxgw9kYBs2/OJNCJjSvdrrxo7o5DTlROLL1a8DAz88eFPd4TKRE9G
         5uVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:mime-version:date
         :message-id:dkim-signature;
        bh=l9iATq9RgX/gLx1ZkH0iM4uf+sqwaDqv9N316R3zFXo=;
        fh=niJvXdQ7gWFJJbec9CVgwYLImkwoirRekFXxfn6OJ2Y=;
        b=Iq6d3941OQx/koHZ6r/a/PpZYqNdvsR2s0lnIjs9IwGcHRSz/9I5vT34ySe0+3ih/k
         uGehOrU8M+w26yPp+i5Il2Ys2b+Znrt/fORZ8zDcs0OHJnAH0VF8mVxW5lZnoV9T0zk6
         AAgQjuD3dsy3P8eVbcaphFQpbVuthm+p5JjZoBS/oGKTK0WwU1E97MdyqFLRCSdosyNu
         m/4s0qwjE+4DZHb+24GMlma4z97vcvXtbAy/R4a2RVK+d7+edGQson22nLv1EsKEvBAg
         NtcbN5tTwHBwcoly94WNoJJ8PE0nQoBuWdOjd4jloZ46OXwXkyOtScS0W2PWDs4I85Fl
         1uHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@iencinas.com header.s=key1 header.b=lcEMBs7h;
       spf=pass (google.com: domain of ignacio@iencinas.com designates 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=ignacio@iencinas.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=iencinas.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742041312; x=1742646112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=l9iATq9RgX/gLx1ZkH0iM4uf+sqwaDqv9N316R3zFXo=;
        b=Msd8MP8aJac3JdnOtZpHt7llm/QAN2H20Wzjs6tLZB2P1WWOEyjNyfSRu5VnMX80Pe
         FnRVxMeH7jjdAz2tqvZ+GyxxbHcRxYLJZNlPgLMZ7H2DoqIq2tvL/PHq6JAGfI/y7gWr
         MH5WbYOfjBYXE9lWKtHZeGvnKpNBJ0eFhwsWrXde3gYmkAkiyuUSYEkpqZpcN/lPfOax
         wYQvXZ5HhX5fdMBCZb7VNZQFQln+TmK9g42kAXq8nfU8HBF/nBY7wWZxL6dRl7/ySxOo
         hPpHTVPi/1ywxhj3pxT0IOq4uJYCcGNPZ5wxfXu/UiuT3L4Hil+KBiafFKOKLdplWNBW
         mSeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742041312; x=1742646112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l9iATq9RgX/gLx1ZkH0iM4uf+sqwaDqv9N316R3zFXo=;
        b=aRWuLtZYmbFLGT92zxxWC4iNEp6TWsKfyPE8rVkEuTawzJimMnnEyscDpWkflJliON
         QdcS/Pm8aIaXGQjCcXb3HOXU1OzGC9np2ck6rHsAD9YwFTbMCyoayMqW6tSamOLRx7WG
         N4JvRLwxHjuh3IY1QPHh3nBt4qug9F41tfSH7aYslmVjhOazvpB+PqRq2+6iJ5rx5+kw
         xY7gGWI2vbSV+Kv6mFc3faN/YxXykrohcla4UuUaxfRM5dPRuy3LzqlI8cvy/Uf3tGoh
         utC6EnlUexR80ip/8tPfgwCT1/XztPGEQwRy5M5U2DMjhpcP3agK/BVq6kAqcMb9w0CI
         yVtA==
X-Forwarded-Encrypted: i=2; AJvYcCVSx4OcAAGDWhJS79WYgllishTHBYXnKAhelEvc7qwG9Dsth3K6jAzRJea40R8MTIXZApuBaw==@lfdr.de
X-Gm-Message-State: AOJu0YwFLRX67XToCaJOqDPIlZ2FsNK54zAQaJsr71HAl5XbgREzKuvO
	whWIAcH8vPbNBi02pCZUrDyA1o6L+E83goLdByzg2nUjxi9IPZr2
X-Google-Smtp-Source: AGHT+IHOgt7UcYPKuMK9S4T4giHRUYvYdM+lUnpP4mol0bUBlsI7Iqxg01DECGDI6biLeKOsghFkxw==
X-Received: by 2002:a05:600c:34d2:b0:43d:4e9:27f3 with SMTP id 5b1f17b1804b1-43d23c9c437mr45863545e9.9.1742041310758;
        Sat, 15 Mar 2025 05:21:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGBiiSJ6gsqDA6pprou8XvhV+Ggcq5uQPzEJYjpnGvmnQ==
Received: by 2002:a05:600c:8a1:b0:43d:2313:7b45 with SMTP id
 5b1f17b1804b1-43d23137bfbls6889725e9.1.-pod-prod-04-eu; Sat, 15 Mar 2025
 05:21:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4+lr1/gr/97jDp66mMYAVc5kAExWWjOOuZN5hy2ecZLs2z09ACRVT66zdhb4We/w8jMN+Wqu/Skc=@googlegroups.com
X-Received: by 2002:a5d:47c4:0:b0:390:fbba:e64b with SMTP id ffacd0b85a97d-3971f7f8f98mr8574525f8f.31.1742041308934;
        Sat, 15 Mar 2025 05:21:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742041308; cv=none;
        d=google.com; s=arc-20240605;
        b=cp5LS0SP/+7FMmIOhyorPxM5DokzoejoQ+yDy+M2VdNCHC+rRjAthNTksmiVy8fj/W
         7a9uFSzrTe/aDDRDGNDmqZUyK4tGVjcgomkejtecQRlS7oX9fxyMFAobZQiwKptbd4/E
         JdRIExFTC0x6CqNX1QxxngiMKyS2ikIHqLIluPZzyCGHAqOt9BpKbbW6nGUfOzb/8wwg
         2uWinsLP9iitghCay1b6tNk9g+8lhJ47/WxKxay6lKoshnkEWVuIQM/s3yvpkWV4g6Gf
         GszGrK449CiTyQAxfNcZN7Y+m6gjp+UxlOhexWou/5phSfuQSTBvflfcVHwrw1f0jBKM
         9b8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:mime-version:date:dkim-signature
         :message-id;
        bh=4pHhzfXW24TF1t1FOgMUb4yg/TvgoSuq5by1lc39Sis=;
        fh=z3zcIhmu8WpQYMuepB5QATbZbRZLmfeZ75oRH+sVB54=;
        b=hOqdw8MZDI8OagDgY8yCtJJLdGK8HYf8LMvIEyQFxcVXRplC3jNwy9adu1sXw+Vy4u
         zR3JTkCTGHghkqmBQL6dawzeGlUSNzaa+YqJ8e1IPKXvvq/VBCgq0KDEqqbeIlUxSXw+
         ksL7FnfynBrTjIQTdOYbyVuO+6EL/Dh77Spb+itymVUBOnIdpIEoHWGHb62D+eGUIQbM
         nJQu2OYgTtfhofkY89S959jjNz0bnHeLBodzdrvnKZJHyWfM73db0Fll7BxSwKBxWgU/
         KRo3Xyx0b2mldGE562wPtrtjIVgb8HVzlD/W4gbCfadYAKexPi3S/bv8l27KeHPMF0Ud
         wolQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@iencinas.com header.s=key1 header.b=lcEMBs7h;
       spf=pass (google.com: domain of ignacio@iencinas.com designates 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=ignacio@iencinas.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=iencinas.com
Received: from out-173.mta0.migadu.com (out-173.mta0.migadu.com. [2001:41d0:1004:224b::ad])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-395ca77c3e6si70378f8f.5.2025.03.15.05.21.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 15 Mar 2025 05:21:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of ignacio@iencinas.com designates 2001:41d0:1004:224b::ad as permitted sender) client-ip=2001:41d0:1004:224b::ad;
Message-ID: <9c6298a2-4efa-4f77-81c0-b2132f48c1b0@iencinas.com>
Date: Sat, 15 Mar 2025 13:21:43 +0100
MIME-Version: 1.0
Subject: Re: [PATCH] Documentation: kcsan: fix "Plain Accesses and Data Races"
 URL in kcsan.rst
To: Akira Yokosawa <akiyks@gmail.com>
Cc: corbet@lwn.net, dvyukov@google.com, elver@google.com,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel-mentees@lists.linux.dev, linux-kernel@vger.kernel.org,
 skhan@linuxfoundation.org, workflows@vger.kernel.org
References: <1d66a62e-faee-4604-9136-f90eddcfa7c0@iencinas.com>
 <c6a697af-281a-4a91-8885-a4478dfe2cef@gmail.com>
Content-Language: en-US
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: "'Ignacio Encinas Rubio' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <c6a697af-281a-4a91-8885-a4478dfe2cef@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: ignacio@iencinas.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@iencinas.com header.s=key1 header.b=lcEMBs7h;       spf=pass
 (google.com: domain of ignacio@iencinas.com designates 2001:41d0:1004:224b::ad
 as permitted sender) smtp.mailfrom=ignacio@iencinas.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=iencinas.com
X-Original-From: Ignacio Encinas Rubio <ignacio@iencinas.com>
Reply-To: Ignacio Encinas Rubio <ignacio@iencinas.com>
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

On 15/3/25 3:41, Akira Yokosawa wrote:
> This might be something Jon would like to keep secret, but ...
> 
> See the message and the thread it belongs at:
> 
>     https://lore.kernel.org/lkml/Pine.LNX.4.44L0.1907310947340.1497-100000@iolanthe.rowland.org/
> 
> It happened in 2019 responding to Mauro's attempt to conversion of
> LKMM docs.
> 
> I haven't see any change in sentiment among LKMM maintainers since.

Thanks for the information!

> Your way forward would be to keep those .txt files *pure plain text"
> and to convert them on-the-fly into reST.  Of course only if such an
> effort sounds worthwhile to you.

With this you mean producing a .rst from the original .txt file using an 
script before building the documentation, right? I'm not sure how hard 
this is, but I can look into it.

> Another approach might be to include those docs literally.
> Similar approach has applied to
> 
>     Documentation/
> 	atomic_t.txt
> 	atomic_bitops.txt
>         memory-barriers.txt

Right, I got to [1]. 

It looks like there are several options here:

  A) Include the text files like in [1]
  B) Explore the "on-the-fly" translation
  C) Do A) and then B)

Does any of the above sound good, Jon?

Thank you both for your time

[1] https://lore.kernel.org/all/20220927160559.97154-7-corbet@lwn.net/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9c6298a2-4efa-4f77-81c0-b2132f48c1b0%40iencinas.com.
