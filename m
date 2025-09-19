Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIPCWXDAMGQEEDY4AZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EFF89B8A2AA
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 17:05:07 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-78ea15d3583sf37240336d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 08:05:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758294306; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wu7/KHmbkoJcVkyLVeYkcLadcm7mqb2nzuNzUm4p08+bpbZ1XjhUcU6YnTbB5rCyDZ
         P2NL8ZpGu+KJ+trCTawvLTCr5O1r/vbt3yfNNpdoT8jGX4h8K4TcrKgsOrSm1JXqhSoJ
         BNKkScPwYJTge7CKEZ8TiQkHQZCqshNhhEjARGgC46gARQJYruY9YcnTTad+XdDo3l/y
         ZksZLukwJcM0CIme76z1SFl6oTvjgOR2nLOXFX5dODgZSzqNCxzFSPaxvHyTsHx08jtw
         VAiJoUlL4aj0POyHQI/8AiQ1BHrAPMG/AaC4eBfm8fLgChxFSlgdB30b46JQTH7vOmGr
         xVhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=m0S4wb5+CvSPbFY8kaFv85rhbprfBa7g49q2dxbRWso=;
        fh=Zfwyspj9+gkrgjezBS1Ck7KGFSRjC6Jnx/OeVRdOp0o=;
        b=gdXkBGsfV0OvKYXWFV9P0lRYe2YvPogK/mpaTZcC2BatqnYEw+PrmrhqXZ5eAXXJCV
         19Z20UeufIok7Wgi7xT+phsl2EXm82o32xgr1Q9WoLBZAAuGzwZQjbls6WvuYHO2uVDJ
         +iy7vc+zMqtCmC9jwpXEwtsxZ1mUVnUdG6ELJLFx+GtGINJ06NvKxWVxQREP6AWrk0XM
         vt0XeCDpOR8nvDjbqW+K/B2JRRFT11CtniFp2cBOtDyilcchc2aYuYrSAho1AIN8APC9
         oQP/xluKYC7YRdAu3Z7Lw7sOtZIc/KCvD9IlyLm/wiaI87K4zAQIhVZYHgSvz28xIzI+
         RtLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jgqoDcMr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758294306; x=1758899106; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=m0S4wb5+CvSPbFY8kaFv85rhbprfBa7g49q2dxbRWso=;
        b=qnyJmpq2Gv5izIu44OBLYQxcmjZdOY3i7Ns8+UPY2C/lZREKpfZzHz1VwJILOu3FAh
         g6CkISm0Fv2CMVt5oVApJgj+TjT8xXXx47wDcPDgADOiN06mb29gFJd9OnPN7NIykIML
         hqqywQJQqbolNTHuAKlax+PXFLWZTyH3Yq2tlVOL52nSgSJKoULDBgsUrwYZXoF7KdZ4
         DTxZsEx6aZ+AeFaBB6Dj8RYglLIG693BqWinm7te2MNzT9t4OZM1DwmPPEBgCKDf/jaw
         JmNZRZ3khHlU9qB3uJF0yXmCMRUWGs96OkKan2EGvViNtkzNllr/3xmC/SD6SNn2PflB
         CRHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758294306; x=1758899106;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=m0S4wb5+CvSPbFY8kaFv85rhbprfBa7g49q2dxbRWso=;
        b=vi2i9UcH8Eh+lTjnwcv1nR205O5tKgpsgcM/iEe2usamDKhQaAE3hbxraqERW9lGrk
         95gG2B0WKuTa2+eS6eizT8zobFWZzyrld6jLwGYPSqOnAEmKW6+OzgUqKckV2lfKb4Fn
         VKFKcG0XhbR4C3ck2XpnBCFDDuXG2eSkgJVwdjp7fjWLEfV+iIFgHkI8CcbgYEWeD4Wt
         jH3G8YW07jySePCkMaafIl02ME7pfSvT7Q9OyxSjfUWecXT/PAtd8UGorw9pqlVKCU90
         SzsUpdvvoiXqz5Noi4YNmvUA/DQ1YSVq7PwYKh49ba0hRElMsueg1l3pkA4Kd/WZlQY/
         x78Q==
X-Forwarded-Encrypted: i=2; AJvYcCXvaR0xse20cLs9GxN0BWjVLuhgolCdAWBejYd48U0iPcP/AIlvinutYvivcIfYXi9npDU9Hg==@lfdr.de
X-Gm-Message-State: AOJu0YzEHhLrO8XSnB0zGS3V/MDSipNvjgg+pHloh3QOwHiktiXLGyGT
	wHPJnYb2ldfp1k+SEl3jocne51fTdC9c35MeH+XQ2nHm/x4lCwaT0QVp
X-Google-Smtp-Source: AGHT+IH5oRV7ADoaeOOq6FCsdxJibMNGav6rJ8AB++03WtAxtB5nVgu0VkjgVV+fmF3NmxgAxXwUcQ==
X-Received: by 2002:ad4:5aa1:0:b0:72a:2cf6:76df with SMTP id 6a1803df08f44-7991b0dbef5mr38585246d6.45.1758294305936;
        Fri, 19 Sep 2025 08:05:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6OQ4stShOfs5WVDG+8CYlQklA4V/UHA3EVnq0Mf1CDqw==
Received: by 2002:a05:6214:224e:b0:725:7cef:3097 with SMTP id
 6a1803df08f44-793361c5e27ls23985836d6.0.-pod-prod-03-us; Fri, 19 Sep 2025
 08:05:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9KjJuVJOyrzYKGmB2ORabodbGWK4T4qP7v9bMAVWwfJ30pDj/WTpvcVkZHxZqLkBepIORlcdsOzI=@googlegroups.com
X-Received: by 2002:ad4:5fc9:0:b0:787:982:2960 with SMTP id 6a1803df08f44-7991c407e57mr35735246d6.53.1758294304546;
        Fri, 19 Sep 2025 08:05:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758294304; cv=none;
        d=google.com; s=arc-20240605;
        b=LuEBwKq3a+OiAuDgw61WlAAePKKT8JdqiKTpcrC6uVkHHzjalkwk0V1y1C5Db/omUj
         LOLGMXzCB/moZX7wzXx5JJ7pV4wdHmtFggcFmfdDMNuolCyvjuciKZEaVJyyFzxSaXt5
         e/qz3VoBzWS3M+wNBvolIb4/FRenwXpk/LlyR9U2Cy/pNMc/173qDzrxhMjPp8YiVmdK
         3U7YftddnIfLNsWAfMwr93WsdCao1zJA6HGs53XsSWLXyJDT6OltfCFyl1x/1nKtGoB6
         /vAzZnWThKzEzjQ1BXhMKgnXbbSMrHCu81nP0/SjJ1w3dt0UOeGN7TJjJ4SgACZLvzHv
         r0pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RGxC493IbjEEger8hKnkve1PTNTnnMKtNGhHQrFJ6n4=;
        fh=wwnzOiGqjOEy2BSj3qXxekd/vKXyOW5MGVesXGFbldc=;
        b=b/439U1P7CS3Jd4Xl+WW7HMY2Oo7gE6QTDdVqvcg5IbuGU6nztv3VUwtGrfQldNDHP
         JMHY4hPZpLGMSIhPoCskIp05UgbJCHDrdPz/fBNkmsrnsEPvUZb3oYuAb9IkWsQRPt3M
         ZKCuafZLHLpaTmv6FZXQPDuxEjuUMPhULFWeVDnHbgFUucKKrI/iNReiP5q0hWspK7V7
         L7A+20ANCyctUpp0T3iMArM9hxmQnmhEwcnkmoRdaB/TATIl0wuwSwxQYzqD5fnXmgtF
         B0kEPAdJUCr/lBPJOKOoBfFuWwvinXNdpvOIUIjmFm2sKPJr/z/TvdMCfZj4DVHBQHfn
         2xdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jgqoDcMr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-79342226ad8si2216536d6.1.2025.09.19.08.05.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 08:05:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-721504645aaso12742416d6.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 08:05:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUMKwJ0Cj2c8ah5YqyMtKwcgkE/3dUC1kQyhZqN8gPnXl1qjOdIj31aFENPJ9LddqbzNDT9SUyMFeQ=@googlegroups.com
X-Gm-Gg: ASbGnctcioYOrhUg4N37oITmsNDbvsLTP4LQjMvcpCj27ZPIcCxWmEUoPCCTgtjX8cM
	DG/pXuwi/VhMuMBLXyl0DlaplrwZvYhT0wwAiNqLgf5GyxDcnBO1w7QAa2iBOJLarhvwbXvns6q
	VN1DqxjXIYaIm7Q9djGYBa06RT5Ze96yFX1Rg1d2j7EF/WACdpKYmCjfubVta4fRtTtv5xuHRHc
	wYLJwTs3fQI3er4goHAp2QpTjAWL5zoI5HAMw==
X-Received: by 2002:a05:6214:e6a:b0:747:b0b8:307 with SMTP id
 6a1803df08f44-79912a7799bmr34142706d6.26.1758294303181; Fri, 19 Sep 2025
 08:05:03 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Sep 2025 17:04:26 +0200
X-Gm-Features: AS18NWDNOJ80ZgwJUanMmHMdQpo3tLnLB0-s453y8IuyYBCYAQcCDLNYEOTyu6E
Message-ID: <CAG_fn=XXvk-okceUAnpwkk5W5kFLecyoNJcVU9Rb3g=M9qA8ig@mail.gmail.com>
Subject: Re: [PATCH v2 0/10] KFuzzTest: a new kernel fuzzing framework
To: Ethan Graham <ethan.w.s.graham@gmail.com>, shuah@kernel.org
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, sj@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jgqoDcMr;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Sep 19, 2025 at 4:58=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> This patch series introduces KFuzzTest, a lightweight framework for
> creating in-kernel fuzz targets for internal kernel functions.

Hi Shuah,
Since these are all fundamentally test code, I was wondering if the
selftests tree would be the appropriate path for merging them?

If you agree, would you be open to picking them up once the review is done?

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXXvk-okceUAnpwkk5W5kFLecyoNJcVU9Rb3g%3DM9qA8ig%40mail.gmail.com.
