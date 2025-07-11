Return-Path: <kasan-dev+bncBCO3PDUQQMDRBS43YXBQMGQERGOKONA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C631EB02309
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 19:45:49 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-32b32ce581bsf10754671fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 10:45:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752255949; cv=pass;
        d=google.com; s=arc-20240605;
        b=YfQ+NuoZSZbu3hBlne2dabs8h/0cpUEKWMvuZ0XKdB49nyndfTCOieM0uL4Wl5tWLH
         BI9yqxIjmwKwlFUaAL4zDKRwF6Bl1BL4YRLYmOrIZ6rej8LHg59RFIhSuC2GKJ2mNC2d
         LX92a8gb20Fdt6s0yj503FD3NONx+msiO9mg2vnW241miMD5uXFw6GkPfaFyL7qGR14T
         tWwkoCwKIR0Khwa3DlNmzOMV94gA33Rni7EUClk84Y7G3bWOvJ+uDtiHs4NzgKxZLJ/c
         IsVIgj18hyuprfGrJHchk/BC1frQqPqKFDPKSONAumUO0aRApWaUpBBNox3ZsLKM4fuJ
         q+HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=YU8GworcYHG5YrbqsueUVfoSEgiHLSn7tyStHP+EQy8=;
        fh=rfDviXfm7pEMpXMB5IB2fC+Sh5H84/SJpJKskoIO6zY=;
        b=Y9rJ2QV/63oMhKCPOivxF0nNXfHLcYBQH3ir2fnbWtt9mh+clfeCWAABH1VxNrHaZF
         0HLMe4E2/yM8xnWe/h5uPKSSCAyp4A6f9C3XPX7DS7sVnoGwJszabBRbRnAQd2cjJuB3
         wGtfJte9EnqTNzyi5r8M/Tax5XpkTCkQe8/WPi2iTRQhq0kHpd7/yBnXzShZXKqsvSQB
         gfhL+2yqVVObgsbd8l73DfkXxbLW2uedQC11KoiCKWRPfK5a88oJ9ojDlsvkb7meKzIY
         XnK1RSyE9rkcva9r81is6Fbr2dD6VuLKRf1Pk4WHXHlAFiWSCljObYuVuqMetau3C9qc
         RyLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="dd/J1ugC";
       spf=pass (google.com: domain of david.laight.linux@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=david.laight.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752255949; x=1752860749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YU8GworcYHG5YrbqsueUVfoSEgiHLSn7tyStHP+EQy8=;
        b=FrYiNWSLqLAI0IZRHYZj+Jlfm4hBiiZ7YlYbhM3SuWT7qChCvvLeTDa2ZuBRFsrgS+
         yGXHYvvCPgDPsbogOnBgSzvRxp0YnMczMZ+7T5VUlll81KEyhtgZ6KihE4fND7xsWlAh
         h1Ly/q3rPLZbSCI6ycjTKX4roVDZOSVYZVhkKouR4Q+g1fLy3F5/4GMxT4vzx1y+M29J
         5DbzVc6f3d4Kg3oVytuIGiN8I5HN5ui27+BdrDNaAopQ/7L4DKGP0ZMMf/v00jFt3wS7
         xAIHS73bjw0J6TvtW3vMbjBOTmXvJU7diQ/n9yZCKK3vQ+mwTWICWJr/zHBtuBpaXt8J
         aXdQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752255949; x=1752860749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=YU8GworcYHG5YrbqsueUVfoSEgiHLSn7tyStHP+EQy8=;
        b=fXBG6pPo0p939cweJ+OTM92mhztqN1OJ5k4gXiFowClvAod2kW1ln9wmC+fL8amXrG
         2YdtrNh8ofCh2fHr5ridZHaG9QZxjyCeWCSydd9StqPWlokw3+8Nt34Nm5Qfn5L3eupV
         uh/CAcW0KZRBcel/XKVWRpy7U0HpHp3T0r5DrOaWveGB0ipeIHGsNxaMNefzgC/7ZBaK
         19fjgNH7LSpfhvWqS0e3cf9UnyYld9vlS2MNJmIsC9IrNPzSPBmgezVsQ90gINBaQEQ9
         95vvyXxy2NoWSIUDGlxjsu77Pc9/GUrpbksZKiLdmtIRqYhOVVzfdbOwhES2vUDrxv5z
         7lDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752255949; x=1752860749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YU8GworcYHG5YrbqsueUVfoSEgiHLSn7tyStHP+EQy8=;
        b=ePQdXnNijnq5i6VaY5jVJNuh9Y1dmOG6GxyBfDIOacj0W+jyQES/VJowF3K6DkHIRa
         eQV5eg2v1f0kkq5JtRvTD8i2hZtsfoNHujEFYYJh4BbeCfo+ASD3938j6vEOm5GIvzWm
         d01DtwiYG73S1+WL3FR07Vjp3OyTZQd/qUZnQCA7iA/sMkjOWXBLlmjSPo7OOPIGQYce
         zklK27ShHWJpWRrKMLlYOEZl08Ey5AjU32JrbZLAxI268y90ulpC29RZYAE/bpeU0mR0
         JBW6MqAFx7lv3m7Lpzi16LUWk84FVX+gGsUb/Ny+PpjJLxR6liqAIzcqqhIQETUTi5by
         hF6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUabRvVADNcsKIoZRCGCrtrMsihRQxDiySG9aufTSSbUD+aT0hcNJ5alhpzy/zJDth29X4WZQ==@lfdr.de
X-Gm-Message-State: AOJu0YznwoFL7wpXe7/nq+2RNDwRm+YTxNTjyzc8hNq83Xl472IPkR+N
	2uzDltp/UpR7424xcJxCtpGv4wDZDUKJi6LnGDPvHBa8mmL5lLOPGPB+
X-Google-Smtp-Source: AGHT+IFWGW4SgTna1sunK/sO7dTaHVexoHmzzav6gLYKvKrz15V0Gq/iff39gjLW2aVE7HBWiKuT/Q==
X-Received: by 2002:a2e:bc1a:0:b0:32a:7826:4d42 with SMTP id 38308e7fff4ca-330535f6807mr15912361fa.31.1752255948397;
        Fri, 11 Jul 2025 10:45:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcew343DC0trRFNyLLN+zLJZF6Et4pssI/3zaAntC3yXg==
Received: by 2002:a2e:a495:0:b0:32f:3f93:212 with SMTP id 38308e7fff4ca-32f4fc45551ls3920821fa.0.-pod-prod-02-eu;
 Fri, 11 Jul 2025 10:45:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWts3VVZ3mqBAYa7MBpe0un3RAb4sxs5yxfKZSYgnyQM8GNn/Ua6t+OjAIrDOEpF9uX4BAAn5Joi3w=@googlegroups.com
X-Received: by 2002:a05:651c:40cc:b0:32b:9652:2c04 with SMTP id 38308e7fff4ca-330535f9cabmr12137631fa.33.1752255944960;
        Fri, 11 Jul 2025 10:45:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752255944; cv=none;
        d=google.com; s=arc-20240605;
        b=MbDKbJQlmSFTx9IoxhIp0QFfnKVsk0j6GsADUNXcBMuSYnQQf1TkgPw+6G0ND2wxIQ
         wr033PeARxqWKjEpKJD6unQVK4BFhu2p5tCG0dfX+3y5TNCbaeoHQ6Woo0emU0QrNyf1
         ZxhLO6q9YEAoOmgaen/Cb60FB9YrYf+vrsIh8Z2OJCrlgwZZkUgT/kNTfNmCftwMo7vC
         SBYVCz8cg4MHiQVr/yXVFxpal7ib4QocewaPQJpO+D5SD8VcKTrdtMI3vS1qdnxwsFpZ
         6TwswGHxzLOGunrpyEap95ycJBZXeyJb3FN5Sr/8vmnNthzIt2IP8eZAxaPiYYut8A/s
         kVDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=aHz90J7wv6UCluJ+wqVTBlJ1tKvrIgBjMeUDsq9gFZU=;
        fh=0FkELGsm11ZeGQKOR2AhGpZezrpmU1ZwMD/NH12MH6w=;
        b=bNZl/Wak//uF9RuIjX0tof5hkekgbtPlBIsEPB3mnKz1+QGzW8U255gS3d2qZonTqs
         F4jZ8QYbGgYaJR1EJWa1rwhE92nrdar87g3ZK0a+KD3kMGy9FZ2oXvhNIAk7ET+ddL6Q
         Er2wDzLHY+XgETHd6lBPElBo1WBmUqSe9/FDOpVdNUvEyKHRjrkqBxBNsYZtL4NiwwZP
         2LuhSiQwt3N87Zlo1nKCBL2xLuOU2RLIDG5ks8Ic+HgVcjEaP+uX9ko+2OwGotHNIFpy
         yuwFy9/hpX3sNeswq+UcNEwg9rHaFqJ31KzQ9XGNeUxuJ9k8P7gFJHXtu4Fije85M1Pg
         YGgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="dd/J1ugC";
       spf=pass (google.com: domain of david.laight.linux@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=david.laight.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fa29f22e5si1191361fa.3.2025.07.11.10.45.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jul 2025 10:45:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight.linux@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3a6cd1a6fecso2356217f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 11 Jul 2025 10:45:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU9WFJT/MMaKhwYmRNkut1PAV2GWqPfuUdNriAbTK8GlQZtEXEURSR9s7O2/uf2/L9Fxx9jUORYQzQ=@googlegroups.com
X-Gm-Gg: ASbGncu4nQezk+hTcJ7DXUihSWowG2EQUhRv+5WRXHxJcntFE2qvxsdxsMYINc32Y0X
	rI2fFslmWhoqciCX5jP9eA4h7zrdaoc/SsTfCHHegDYSNXS26Wtxia52i6jYZgL5FVIfgUgUJnh
	QIG1I8o0NkhtnRla5+0Xei/KDj9YMCcYZ1/L1F5kQkTSExfXF9QrxiQKYLIC3/ewYv0LdjuiR6g
	6XCxjVBwPQqAeqo6XpPS9WHrvuQ+PEYKToxMWRbfvR1Ic2p9inP26nLp6udUP8WW2vvKEEoOxIk
	gQdAxYuXRCrDyptwxrpDKWTX7ofQe1CNVAgK3QYq/kmGgZ10vWMer+r6kCTAsNsuhZGQnX9jejx
	FafxTn/OjNGGxwIkqfG3hivOoQm4mH3y/ViMWf8fETWDEf69zTpjtW6IpAbOejMrV
X-Received: by 2002:a05:6000:645:b0:3a4:ffec:ee8e with SMTP id ffacd0b85a97d-3b5f188eb07mr3981761f8f.36.1752255944008;
        Fri, 11 Jul 2025 10:45:44 -0700 (PDT)
Received: from pumpkin (host-92-21-58-28.as13285.net. [92.21.58.28])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b5e8bd18ffsm4957337f8f.9.2025.07.11.10.45.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jul 2025 10:45:43 -0700 (PDT)
Date: Fri, 11 Jul 2025 18:45:41 +0100
From: David Laight <david.laight.linux@gmail.com>
To: Martin Uecker <ma.uecker@gmail.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, Alejandro Colomar 
 <alx@kernel.org>, linux-mm@kvack.org, linux-hardening@vger.kernel.org, Kees
 Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>,
 shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, Andrew
 Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry
 Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco
 Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, David Rientjes
 <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin
 <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, Andrew
 Clayton <andrew@digital-domain.net>, Rasmus Villemoes
 <linux@rasmusvillemoes.dk>, Michal Hocko <mhocko@suse.com>, Al Viro
 <viro@zeniv.linux.org.uk>, Sam James <sam@gentoo.org>, Andrew Pinski
 <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <20250711184541.68d770b9@pumpkin>
In-Reply-To: <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
References: <cover.1751823326.git.alx@kernel.org>
	<cover.1752182685.git.alx@kernel.org>
	<04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
	<CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
	<28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.38; arm-unknown-linux-gnueabihf)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight.linux@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="dd/J1ugC";       spf=pass
 (google.com: domain of david.laight.linux@gmail.com designates
 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=david.laight.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Fri, 11 Jul 2025 08:05:38 +0200
Martin Uecker <ma.uecker@gmail.com> wrote:

> Am Donnerstag, dem 10.07.2025 um 14:58 -0700 schrieb Linus Torvalds:
> > On Thu, 10 Jul 2025 at 14:31, Alejandro Colomar <alx@kernel.org> wrote:  
> > > 
> > > These macros are essentially the same as the 2-argument version of
> > > strscpy(), but with a formatted string, and returning a pointer to the
> > > terminating '\0' (or NULL, on error).  
> > 
> > No.
> > 
> > Stop this garbage.
> > 
> > You took my suggestion, and then you messed it up.
> > 
> > Your version of sprintf_array() is broken. It evaluates 'a' twice.
> > Because unlike ARRAY_SIZE(), your broken ENDOF() macro evaluates the
> > argument.
> > 
> > And you did it for no reason I can see. You said that you wanted to
> > return the end of the resulting string, but the fact is, not a single
> > user seems to care, and honestly, I think it would be wrong to care.
> > The size of the result is likely the more useful thing, or you could
> > even make these 'void' or something.
> > 
> > But instead you made the macro be dangerous to use.
> > 
> > This kind of churn is WRONG. It _looks_ like a cleanup that doesn't
> > change anything, but then it has subtle bugs that will come and bite
> > us later because you did things wrong.
> > 
> > I'm NAK'ing all of this. This is BAD. Cleanup patches had better be
> > fundamentally correct, not introduce broken "helpers" that will make
> > for really subtle bugs.
> > 
> > Maybe nobody ever ends up having that first argument with a side
> > effect. MAYBE. It's still very very wrong.
> > 
> >                 Linus  
> 
> What I am puzzled about is that - if you revise your string APIs -,
> you do not directly go for a safe abstraction that combines length
> and pointer and instead keep using these fragile 80s-style string
> functions and open-coded pointer and size computations that everybody
> gets wrong all the time.
> 
> String handling could also look like this:

What does that actually look like behind all the #defines and generics?
It it continually doing malloc/free it is pretty much inappropriate
for a lot of system/kernel code.

	David

> 
> 
> https://godbolt.org/z/dqGz9b4sM
> 
> and be completely bounds safe.
> 
> (Note that those function abort() on allocation failure, but this
> is an unfinished demo and also not for kernel use. Also I need to
> rewrite this using string views.)
> 
> 
> Martin
> 
> 
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250711184541.68d770b9%40pumpkin.
