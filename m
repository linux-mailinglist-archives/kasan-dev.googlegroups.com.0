Return-Path: <kasan-dev+bncBC7OBJGL2MHBB45URO7QMGQEBZIQVKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id E19B0A706EC
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 17:31:49 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-7271d7436acsf8456683a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 09:31:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742920308; cv=pass;
        d=google.com; s=arc-20240605;
        b=BEfZmpNMw/uqvE5oYsZ+UVq7TkBNjCVyO6PKFpcrWrBp+GQd10XFqCytq+BYbYd5tY
         A4C2kOwHxLNV6cFXtMGizXBWXI/PRWFhpDUx8NS9qXaCjfLDLRHKOAZXRKFa+BZqMZKK
         k1wzk9SFzYLtP+Rf37vd2+DWrC9UgyaGhVA5MuNKiU4SVCx9LVgKWUhMjCNFr+ZvqcAg
         rA2o5w3OmBzWlebbDLYf0XbOTmWPKOcwBskShFDRc6pWh/tC5LfIMPqHteoxu9UbmRgy
         tXnoU2mZGESazuQLCrtNafMpjTnHEDCN1c/FKGoptruVFi+f7CrGcl8z8HXL6SoJ6PEp
         dJCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0qY4mAKpbXbur9pr7DSAbkxXZ9TvXhdmDqIzfHBbft4=;
        fh=w9m7Ty5XAhgLMFqE+X+NpG52s742nCXJuVgA3g+EAis=;
        b=OqVDhze9AEpp+G+8UtfLr3TATjW4texUcAeMwKrsKa7XGP1WdQ4AQdjj+9cK5/PlrS
         nMsaRyRQa5YTL8zFcA16F5bayXViboEIlA7bs0qtOMJkhhMFRZ1wSDw4MPwNaxgo91Fs
         VTTYcLdU2K7mj+EvfiBv8IcgZDyqPLNUg7EWBjwWnLcJqpiKpJPC81glCgXxT0GEC4d1
         1Xf5vPjsMM6PE4RSH6vKlAfBuzmT/YAjUslalprNFJzA4jp1JSeH8DnF7AO2BYCl7fwT
         sbr1FodZQ6qQzlpi6vt5/CcoUrk14PPwKl56kPx2Sz3Kzu1lghjPANJMj+cLhou4SH95
         OwvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dHRhKHIN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742920308; x=1743525108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0qY4mAKpbXbur9pr7DSAbkxXZ9TvXhdmDqIzfHBbft4=;
        b=W3flG0tk4pHpVOWa4w0Vyu3Vy4SQ8xc4d4OlgQykpppIKFXt/B8vRCDPllqs8R6mpr
         /gSC/rqQ4aPhyFqM3YoKoA5eqBP2CYbblFqwdvVvLd8mSmknrR5sM6l+ZhfNL1dGMz8V
         4TY39VQT6/tPqiNQOAbLAAIbJVgQI6fpK84eFjHnNTGWbtJUem8y449JzEj+a4HM0NV/
         7dHKcNUAemziFsgxnzbaUihAZnEw9fJ0kr8MiKjXdh3kWFFEvL1dl39GvrFhcaSrTvgn
         tb+Wsv96USDyz4PLJmewtVVYR8Zuyj2NPl1I6kAWHFSNGxHD+50sLjG9ai4nYHPkiq3U
         uF1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742920308; x=1743525108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0qY4mAKpbXbur9pr7DSAbkxXZ9TvXhdmDqIzfHBbft4=;
        b=edQEWZHNdOFfJRQcUrqqQ5DuuvSdyVSqJlfRuEtwR9UzXSpKlrG9d6LZPBXbQxDfGi
         gNCL59UQlz8Qhgx1OtdkB1gQXUtv0ixygBRJb7HEdOQqlpqAhfnAiPsF8DSXoT+ZYMvK
         W04qey4YxMxFOAZo7cs2JaYcgdmumNUa06Xs+WYB5G62f9h21lOEnQCeDYaiCY4RfLBE
         Et6oQHDUzXVFsAVlH3cPN171nrJLYyu3/rRw8vkmOOjxA/EbEpRG8ZiIiMqmd3IGqqmf
         AxG4d6iIw/CSsjRgh+q6A3NTroKfR/3SWvy5+RPjPfOVoj2iZNBVxIRLMzqC5XpkQnkV
         XFzQ==
X-Forwarded-Encrypted: i=2; AJvYcCX1FNKrt4F5BP9a8L5GStxzclDHywO2vmNjhPFfjXtxYt5Z5kddrt4M8QQ/x4XVqBop/TKQzg==@lfdr.de
X-Gm-Message-State: AOJu0YxxfUVNxv+C94/WQ3DVEdyt1vKiQkMYynEoDXjErLgjvCWFX/5Y
	pfsH1aaksGmjBsIIzCZzndvxkPKcHoQHP+zkNuQ9F7N5oiNR8lL5
X-Google-Smtp-Source: AGHT+IH0i93xlOtxHlhqbkJOrbNdCRAcPRjjy/7PmECQXJwVdYT+Fi0cWe7WmTLup0bnMT6yU2zGsw==
X-Received: by 2002:a05:6830:6610:b0:72b:9180:cc75 with SMTP id 46e09a7af769-72c0ae5f93amr11146526a34.7.1742920308159;
        Tue, 25 Mar 2025 09:31:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAK7WoH82pDikqbUBQ2U4qCuL9qtZpX2Gm2ImlbWlrPNEw==
Received: by 2002:a4a:e685:0:b0:601:fde0:c9e7 with SMTP id 006d021491bc7-602328c9720ls165151eaf.1.-pod-prod-08-us;
 Tue, 25 Mar 2025 09:31:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUdR1uoCKAFQSBKoo0Dln3T+YX4jBjPSED8B+Ly0jUpkMx2U7+VBZkGydDmf63hjx+nKmN96c7e1TU=@googlegroups.com
X-Received: by 2002:a05:6808:180e:b0:3f7:d16c:e293 with SMTP id 5614622812f47-3febf70b0f3mr10688718b6e.2.1742920306755;
        Tue, 25 Mar 2025 09:31:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742920306; cv=none;
        d=google.com; s=arc-20240605;
        b=NxL9zQBlgpT8nVWbTR99NoUM2zIXEXvM6HsxlLflo+XXZSXrLGwUj+pPa6+2F6rVCT
         PktMcgitaMxaMtAHvD9OBQIfjRaAeMKzPtTTP9Dsqo8Fnpg8TRTmvyWH5RXI5C2fdT1A
         i+NfJHg+V9GgpFFyaiiFQJ+dSRE29t+t0nwDHPstWtGEPXg3aGIijlgJLeQIeY0mAiwI
         4D5pC4hOZgn/BhPrEd0huodhXOjhomy0JD7xFVgRPWRYgT4G8dJJIJOGpMTxSGmw7g06
         R6bXWOhAuq7DXbIOKe4fAqK9M9rm2ATvyZyS39rILxNsLWxZSTW5kYJhYAC02j+RWH3l
         M1yA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FqCTIgh8QO/t7KPUealsnN0UqFbnMBx72fTK2JxImZA=;
        fh=zXl4WdpcaxoOyrJ4jcR0AWePIHEAiD0Lz4kTQsz8eb8=;
        b=RO7Ia9c0CApAgccTybIy0lm0DqMKCUHICY5LA7P50efcLfHkrzSsG1f0385Imj6dCc
         L77eZ5cokelFypdo6vwdod0lRdb77G54/53i9KSOgtkW0U/nYQUSQGWUZjsRV5fvxoFc
         WGMqH1sibxtmrTTCXPFnl417FkEqtp1yGIwCUCSoqqYA8D0/je/IU7jysQi21XXIOhpI
         n0r5xTG5dD73jLKEP2V2HM6H9tataWMyZfXUQeq/J5ZRMte/JHb7Jvw3glxgTu6MO6Zm
         ImXIgV0l5Wuvz3KB8pvUgIHA6dvZaoIHMfQ1tc40PNOGN7LxJktgx2fiIY9ZjYsgrNHD
         DuEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dHRhKHIN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3febf76fcf6si519713b6e.4.2025.03.25.09.31.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Mar 2025 09:31:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-22409077c06so127412585ad.1
        for <kasan-dev@googlegroups.com>; Tue, 25 Mar 2025 09:31:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXvaZqrrEn7dbaejE+L4ps4xkcuO6G1o73lRR9Xu/vpo7Scw1O+z5EcsIKeIXL3M2+3z4nz+mlwbFY=@googlegroups.com
X-Gm-Gg: ASbGnctbqyLcqzY+b3Q4PTQbkdlRlIKlt7kSjbi9KNh3wRRndQryTmmoisnlyTW1lWV
	Ac5hLOfBvkc620WSHe4D0J/SGwr6eew0Bft7eQ2H//G75oEqWSCKde+/1gaufUjXyqi1zr78UEm
	twa6Fn/xbbNLUpro30szqrvn9Pw8GF3FPuAyTDOlHxWGqVSQDRycbzaCGKAReQ3Zmt
X-Received: by 2002:a17:90b:4a44:b0:2f4:4003:f3d4 with SMTP id
 98e67ed59e1d1-3030ff08e4amr26346030a91.30.1742920305908; Tue, 25 Mar 2025
 09:31:45 -0700 (PDT)
MIME-Version: 1.0
References: <20250325-kcsan-rwonce-v1-1-36b3833a66ae@google.com> <26df580c-b2cc-4bb0-b15b-4e9b74897ff0@app.fastmail.com>
In-Reply-To: <26df580c-b2cc-4bb0-b15b-4e9b74897ff0@app.fastmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 25 Mar 2025 17:31:09 +0100
X-Gm-Features: AQ5f1JpE-9eEvuTImZnrBRyMVLS4S4ftn6GcJfbHDvLlEcvUIVnaUo1LgJcC6PM
Message-ID: <CANpmjNMGr8-r_uPRMhwBGX42hbV+pavL7n1+zyBK167ZT7=nmA@mail.gmail.com>
Subject: Re: [PATCH] rwonce: handle KCSAN like KASAN in read_word_at_a_time()
To: Arnd Bergmann <arnd@arndb.de>
Cc: Jann Horn <jannh@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Linux-Arch <linux-arch@vger.kernel.org>, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=dHRhKHIN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as
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

On Tue, 25 Mar 2025 at 17:06, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Tue, Mar 25, 2025, at 17:01, Jann Horn wrote:
> > Fixes: dfd402a4c4ba ("kcsan: Add Kernel Concurrency Sanitizer infrastructure")
> > Signed-off-by: Jann Horn <jannh@google.com>
>
> Acked-by: Arnd Bergmann <arnd@arndb.de>

Acked-by: Marco Elver <elver@google.com>

> > ---
> > This is a low-priority fix. I've never actually hit this issue with
> > upstream KCSAN.
> > (I only noticed it because I... err... hooked up KASAN to the KCSAN
> > hooks. Long story.)

Sounds exciting... ;-)

> > I'm not sure if this should go through Arnd's tree (because it's in
> > rwonce.h) or Marco's (because it's a KCSAN thing).
> > Going through Marco's tree (after getting an Ack from Arnd) might
> > work a little better for me, I may or may not have more KCSAN patches
> > in the future.
>
> I agree it's easier if Marco takes it through his tree, as this
> is something I rarely touch.
>
> If Marco has nothing else pending for 6.15, I can take it though.

I have nothing pending yet. Unless you're very certain there'll be
more KCSAN patches, I'd suggest that Arnd can take it. I'm fine with
KCSAN-related patches that aren't strongly dependent on each other
outside kernel/kcsan to go through whichever tree is closest.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMGr8-r_uPRMhwBGX42hbV%2BpavL7n1%2BzyBK167ZT7%3DnmA%40mail.gmail.com.
