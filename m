Return-Path: <kasan-dev+bncBCF5XGNWYQBRBSFOVKXAMGQEVE2FUNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id F366185210E
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:10:17 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1d542680c9csf46152315ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:10:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707775816; cv=pass;
        d=google.com; s=arc-20160816;
        b=eFOFSiyiexA3FGzaWKZp2Vy96DHc/bb1hsRnl42t3RkCUiQVHFgbMkbMB3sNuTuG9Q
         xE4HN8pOVemq/gddQaJltIB6y1Uh9GPW2gDgKXccjLczGBlbS//oJw7zXGy2q2yr4atj
         aHoi8E2UeZHVVqMQXBtFTjI4VA+q5rjD2TMfca5CE2r8vP0/QXFW5rzeW8G4wosp3Bdg
         1MFQCEgcPFdHWKXoV+KtDmcFJGsFw9rhUn3ocLOO3RNDx1S3nUXSuU4X+/6Ugx7pf6FG
         3SU8Hg2jVXoKC4pB1pnMX9AoqBZ5n2vOHEVNko81EfPVJSVHCq+k4iGPjIQ8r5d8nFUH
         NnuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=SSs5bVfJas+vpR5+fRdTgRJi47pMOVWpgdJiVYPSOdQ=;
        fh=uhpjKxNrfMoIfa4hPTqKn2srt3sI2xZVa2Ujltkmtl0=;
        b=kaa1IlcUhSv0GL2Qv2a49GJPYjnQYgeE8sRwsb6DQIsPDkagVaW7cKoPPhathpZsZA
         /9mjDq21892QtUNnIOkZhF9xNmazP519LqcJCV1Ing+eIciBAjjPzOMT7y/cze/alo83
         gizU/PRQ5eggjxra7tMrCp04DDlkk/+F5ENOWMtWi5SZwWxCqDgo8gHfcX+dO0AVUl7c
         NlhEJnNS3JVr/BgvCcnPDJjP3VYiZH4iUewHn1gsWCNDZaGxWD6nb43Rhq2EiiisQsoR
         /9ss60sDbBz/NYdBvrJCiyvdfUDctBH1hCl6c4mXvVfAFbLiYwn2pADiWMwyQmMKuKyB
         BlhA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mooWlqae;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707775816; x=1708380616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SSs5bVfJas+vpR5+fRdTgRJi47pMOVWpgdJiVYPSOdQ=;
        b=bJhAExipOFcttFc8PIN0oB8Mm85XISMwF+2pwkh2LedDuLj6r7m2MVaAhOLB7drKyq
         MMUqcgBoqtarWVgjTuFMSHaK2jUCJmtsalVeAdbuEsA86m/x2P0yW0UKe+LKEi/KkKbH
         Ai+jssHztwy92DxQUsyOSXdJaX3eSiFZbH9AxChzGEKL2URNdn8cNdCcR9E+MaGHytIg
         mrzsvwS8l6JXb1yOUgcSEW8yiYzGucJnnrnhjE8tlOBWiTAICDhPJDXcz58jEhVoqqg6
         0C5p+s1X+DXVLR2n17Qs6WmP5Es28Cw9TI8xv245Ueckmy5W5sa9De8NB8c7jEGxjrdT
         rpbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707775816; x=1708380616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SSs5bVfJas+vpR5+fRdTgRJi47pMOVWpgdJiVYPSOdQ=;
        b=mw+J23RUaquKyeia8kLqcXZJTJ8E5qjLTyCjrDhPMLATCZn8uda5zabf1N7DgyTpVg
         MB1jYmIqQRQ/+18Q0rZtKrEHKvvr3PA+gF1fN955b5P/VHpaSHNjkYJDWqIap7OlZrD8
         WPzUIEbiE5YwJB0uB69/P+VRA4tKTlIBrRMfmA35gDiP1G3VG1IgxX+d4CQviVGcEBpG
         ctcDJt2SPIXwW00W7Hc2nMkLAC2rE9g5RYUvrPfgo5l6db8RVb5GotdK/al3Vw6EvYxy
         /dIE20FiYHnC6JCuG5pIwU83qMXKtF03+tE4z0nIuBzt4sHvHIMPvAzyrcgsNc+evwbA
         XR6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU1ipcmDeQJQ9FMW6hpxo9/Yl6lsKQR9QBj38KjX9ZLDsu51q2j5dwJ3BRrmMq698jHjSWYsO8TG7oecwCA6QQJWRkWkc8FsQ==
X-Gm-Message-State: AOJu0YzPGYGI1c+j/0kHrBdXzkxh8SnBqoYMp0DLrBcwBWFI8ywbZ5Jt
	bhawjfh7vUwRPdQBcqGvCYlfYumlBUBj+atyxJ6PXDBja88N2Xoj
X-Google-Smtp-Source: AGHT+IGGzaFGMJUxCL/Ya2mxUT+I9nxmUxMJUnzG4lOK46ZESsrW0uWuD25Q5Q6frcJMMD1gpOIFTQ==
X-Received: by 2002:a17:90a:de83:b0:296:235b:ac61 with SMTP id n3-20020a17090ade8300b00296235bac61mr4846803pjv.32.1707775816530;
        Mon, 12 Feb 2024 14:10:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c10e:b0:297:312c:7477 with SMTP id
 q14-20020a17090ac10e00b00297312c7477ls694851pjt.0.-pod-prod-01-us; Mon, 12
 Feb 2024 14:10:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVPQoXYHmluze5/41mMov8GVaVpeRn1JwqIensHEI5sV3FCLReSMwcASGPhQlb/9OOC2SY8/zwtIqw+kNmmq5JuS7++VC6MQksuJg==
X-Received: by 2002:a17:90a:ea85:b0:295:d223:ad11 with SMTP id h5-20020a17090aea8500b00295d223ad11mr4770485pjz.36.1707775815550;
        Mon, 12 Feb 2024 14:10:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707775815; cv=none;
        d=google.com; s=arc-20160816;
        b=06p/NjcQjYqZBSGp1LcZ3UhH4bDwLcP5l1cGfwo5GDdlZit70jOWkk+NrTpK9l+CXp
         TlQzIHmORPG2A8Qwpw16wPh+YA+vi+pn01yeUQtuvrCpCzrmAzt1NVMwekNXjNsX1d8y
         HSQCo/F5ETel6AOwZz76n4UBR2XwdAp1md5loTAzsXisFSpv9sG2RXNqQVNDoZUHKgLA
         bzaykYBi7t2kuthSOUcgNOyxD3967Y7RAnSMOENapWumtGLsA7LedtqVpNiwnP0zIMdx
         UcCU5yWUxLOm9EJcfbWAqgDCHIhliw2hAGQpzwma4wwvl4T96NP7VeD52UadjgHS/4jv
         kuRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=SkGi1YlkpzrNgkK7fsGdO+nBxolzeU4HsB6lcpcl19k=;
        fh=FGr9ppFjwVSziGtmEngpKmcyq8PwXLptODh7xUPssmE=;
        b=Wx6IpAwbUMOPy6r1rCDhD8PfzHsvsHB7hFPM8fqWefgxPkoZst8wCPaex6ArN6p3yf
         zc1Ji0A9LpeOJhVv14Mk+Q9SGIWPlPbTXPiX/BAz+HZCqyXAlm4se7CsdrvUolX/uRed
         JJcQFXt+vlKOdE9IOzIRfpiLQrRxONeV2+R5euz+EvHgSeIeqm5yNN5Xh9e8bbtIKly9
         oxzUUQvouQTYb4Ez+FIMxDPpS1xt3zCzR/nEYs1kmBILC/B9YenoP7ZoL31DPMQyTat5
         aoVdT+rE9M/DXcNPcPjf9RZ0w8pbqny75EE/hwxgCceo7zBqLBOp112uQJ6+SRTBBMo2
         Z7sw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mooWlqae;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCWCmk+zmpECtqcvpxoKDsEVZmQBqdfk9PHEu9SEqvnAy+MXxKB9A71fWETjsNHH2OEMbTk9s8opy96ZFdNgblZ3aro9AcD7QZwv7A==
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id p1-20020a17090ab90100b0029707e11694si132919pjr.1.2024.02.12.14.10.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:10:15 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-1d71cb97937so35121145ad.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:10:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXg8IR3JPX5D1wUrfNGT1QFB0J3pZqsY4Hb7ZPdNbPGSPs0O0pKRvtix2BzJVk/j2QZibUXZq+A4mVWq9JayVg3swqbuachnBjzdQ==
X-Received: by 2002:a17:90b:368a:b0:296:416e:ce88 with SMTP id mj10-20020a17090b368a00b00296416ece88mr4098818pjb.49.1707775815257;
        Mon, 12 Feb 2024 14:10:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUpdF/Y8DBZBxfNBdD0B5iOI8dVkHZAmLR/DBegKiiPdyoVsMB1nLqp9B12YR/ivSLUwI1ZziLaZst+j8+RII/J/NCgALyn/+4rG4J0S3NMBKFwk+Rb4/FRYHQ2nJPW62LK2IdDpFkZBB+2hYrvuWHCHWCiSJTfWIR6+JkqpdFMQVyDsAsh1/p3PAodMrb71yuI2eragivL80AqT/RRXZ910b5e+OU3z2UlMA9mMM2byZ5nU0FTOOKXvXGJKMjNSXWidUFP548IRQ03pwnCVvhyc416Hz0oa5UxInbT4ncwOemIXr4q3bzya9xRKGLaXeFwK3gmcLP5qeit/lmIY7Bm8rgLUvYEmnv8Eitbc/+v0XHS00E/ETXTONSl6YvFZ+7Z6hHq0vs/q/+nX05f22ME9viLeaJW8YGjknL6wLkg7utP9d+g09H7lDxUsc3nfLKVAbe0qAjbGWyu64vGFfZveEglNjjpDBLwTGucjpmZEoWVuWcEUp6g2aw9Qgd0FgJBqjUd3sqPdPYee7txlWVcU6EKtYnVLcLT6CjXFlcCuSw+wrYyKPmD/vE+n4nRlj7PxfyFxwCtSAp67sTbtk8tgLijAl2IxfcWpBq5mgxlPioyIqG5DOjZsDA7MBwkPhZ09WFcykviUmjFc0lXW6sXHGj57TWOzOAoiFGpKEN1496slsW0oSf4A7fLZVD+Gtog6BJH3mMT0TPes+irjuV9JtbB9tRRj0akxwSEeUV3uDrtQvTQAANwupaW9kBG3y6UA9IPi+l39Ue3b3dx8bvN4Gzq3nRiZ7uS/rI57URuKPRdY+36hkwm3692ZDwf7cBa6daXnXP05uxfTCNh97ZuxmlwKkeOXEsw3KURVfHZSYCKWU/HFRNStku0q3L8HTkDVXfFGcW2NA/FyD0sXpIf7Yr6206sEb8r75/YXEvZItGqHJ+m6l6Soj8hP0EsGxlyHW
 3zc5nTOxnkxPz8RU20l95HlSYJ+Qxb66dO6CgSDHFacz5bOAA3ypc0aVE/oKPR9JmdI1RIYmrL+IGub8FH2s+kbZUN+0SZNIcVTGj3yngxk22SXUbej4xeydT760/dpFXAK2P5JBzEPGeWT8QdKkpt/jqaSfJBTs46EB4kzVSZFDCFHyvCiNev9aHbaBuF1HA5hgs6CUj2FaQHcggm/7YwMs6x1rGUb29pnbTNiZsO2dY2439r1lCR9U2WOuQ08gaQ08VQg+8RdDXJkC4U2t9+BZvu1dAAUK2BP4i50DdpHeDDF5ZTkkDSU439xEYc3nsNRBOyN9zYH9Rh2P25uh5xAIw4xfAUTFLHWQ6a5qd/N8NP1ImqmBtd3yfXLg1pK7Mb3hCe+LM7WZBCME2mfj4BT7/LFTUKtlH3Ead+Zsh8Jw+VEyVka+XbXvW8wRE=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id rr16-20020a17090b2b5000b00296a23e407csm1030934pjb.7.2024.02.12.14.10.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:10:14 -0800 (PST)
Date: Mon, 12 Feb 2024 14:10:14 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
Subject: Re: [PATCH v3 04/35] mm: enumerate all gfp flags
Message-ID: <202402121410.2AC4CACAE@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-5-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20240212213922.783301-5-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=mooWlqae;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:38:50PM -0800, Suren Baghdasaryan wrote:
> Introduce GFP bits enumeration to let compiler track the number of used
> bits (which depends on the config options) instead of hardcoding them.
> That simplifies __GFP_BITS_SHIFT calculation.
>=20
> Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Yeah, looks good.

Reviewed-by: Kees Cook <keescook@chromium.org>

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202402121410.2AC4CACAE%40keescook.
