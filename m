Return-Path: <kasan-dev+bncBCF5XGNWYQBRB3UXW6YAMGQE6ZZAQMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 346F5897AD9
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 23:36:48 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id ada2fe7eead31-4766bd576fdsf157109137.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 14:36:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712180207; cv=pass;
        d=google.com; s=arc-20160816;
        b=xvuc9e9gTCoP4yOlhhGd/C5HLHJS7nNZ661yvqlahoyDDMZClEns2UeSncsvMcvb6M
         swYm5+qXIEpsZbGG/MWFSc2IQDET19OEtzjgr/j6pGw8KBPrS8Ngcg0Utn3If+rJ/DjG
         3qyX9v26TqvNgHlhy00zhnrmcV5WMojYufZXJSQf/bQJROCGIJ8WHhEaDDTTMHrCs1/4
         +JZGfL826KyDkubWsdrq5E3dV3q6WrPb/7fx3tPnlU37lKGU4VJ15PshErvRQqiiGq+R
         VjgGVpcozBdjVNGHYgVIBbhWZ9JZzpT2xTAZ0D/zJfIvqcbdAysOnHZBroOSJSsCOJ+d
         DXHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ADMNJWrW2GgW6fu7+2Wq48vyXsmIZU7t3VFstP0U3IY=;
        fh=zBjmA87ZIZ7TCNK0WAzqskygIaIjT4a8WC8cbcqp2OU=;
        b=GuNJlBRaDr1cS7PANeUjVK7hq+1XOi8DNf2ClYPlSrFnrGv0fGGPXJK8iAkoReoV7/
         khmVgQDx5Ul5sT9QxUNwiKepdMPKZ6qFnp8KNz+GQpBEQlPpEQ/WMZuGhpIts+lVyJqH
         QMYu0soZem3Z+ZWWnas9FPKjxpIqV0bQF5RZ7Ev/MAfngsQk+9f3/BwCmGkOEktpER7E
         +vsf21ebFDzrT7nhrBXExzIp4zKfk8ruwnm3YrShhpnArBk30uN1m5SxyxhdmrUi459P
         Rw6j9g11ZNoiItZfgZX4KdIuZnbw+pl4NGaW/hEtC7bVaZGd+ciPgYKEcdYvvLRK/XS2
         BhvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mkLzpioX;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712180207; x=1712785007; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ADMNJWrW2GgW6fu7+2Wq48vyXsmIZU7t3VFstP0U3IY=;
        b=hVv8uutcUFsJCaMTZ+Rns/Wfg5DHq6BgNyHE6fl6g3B5ZS68Wue9PBi91ldjT4OwOC
         4F2ViIpRP9E7xU54SFYy+oap3S4W4DASFm/dLE5Ff7nxbxEhgZx31k1muJsQ/8mAzLXt
         Zz75ELeOkIJn4yuFhj8zLsgOcs0UYhHKNd8jsRfFfmO7Fo83XEGoJeT685tvYijWreVc
         mjLQT1ayCdwDMm5cdJtctaEGAQZvTR4SHzvfUQuJv6r5g4bv525COfm5TA4wR2rFEkYB
         oDeO/0hK0p0ku1AD/DCUIYJPMuHK9f+acJzJUkZt8ZwcrtnTkkShfPx9aNsNCsXNJKIE
         5DLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712180207; x=1712785007;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ADMNJWrW2GgW6fu7+2Wq48vyXsmIZU7t3VFstP0U3IY=;
        b=oS9HBI1cIevYJaiI8nDfOY1iAzOW1TVPMsnKhFed6ysHrokn2LNcdQ39gzb1MpzCis
         b0HfrGXhkqJZzENWWj99r99JaAnDSfmo+yqXywxWZXRezBs9Zu+/no8I9WjuutcxcB/u
         RX7k8B2tmEaHJZ6xCS98GuJEzX5+TOInnC5/+I1v3EPQPIC65eSEXh1GaCzkW6jaThFf
         BDbfhUqvQUN6dLCboZgU2fbjdKAWEvd1OYwpfXAoWD6qINadtF4yghDWfynLspTyoBZN
         Jmr+xFkAavHz06zK0wwD2UYm+RYMt1QYXJS09+YDR5U3OPeowo55XFh5poqVt/k+y+My
         WREw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcJOyxCpnMn+T0//wooxqzT0rvKPTutEamZBxGj2cqleFQ5zT+RjwZjXUTtSOIhJi80CRvjM4hHtko5EmTd08Xy4GUHzw6+A==
X-Gm-Message-State: AOJu0Yw1Yli8zByJKZmhZ92iI7vuQ9u2NclNPSQ3yCK2XPxmRlwIbSE/
	PW7xeuLjEMonRi8UqVw97U0kKoe2MDE1WucBEEhIzDAQeJiAfqwB
X-Google-Smtp-Source: AGHT+IEdt6Ki0nOOqaTXSNCPmNalvBieTRLDOfzE298+yziMIuf8RB2nKsphKnzc+z4D/N75JtBgqA==
X-Received: by 2002:a05:6102:668:b0:476:c866:8d4 with SMTP id z8-20020a056102066800b00476c86608d4mr575069vsf.3.1712180206612;
        Wed, 03 Apr 2024 14:36:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:b66:b0:698:7a54:d877 with SMTP id
 ey6-20020a0562140b6600b006987a54d877ls555234qvb.2.-pod-prod-05-us; Wed, 03
 Apr 2024 14:36:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVGterYE5yj9OYWsfj+QklP+JeZ5GFj++pNmwwb7/QYuJjW7oMY2B3ozNKuuuyCBbRWLs6qt/RYpLNNTgUn9b5+J2zfnzZSpH3jCw==
X-Received: by 2002:a05:6214:1316:b0:699:1f58:398c with SMTP id pn22-20020a056214131600b006991f58398cmr637186qvb.5.1712180205455;
        Wed, 03 Apr 2024 14:36:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712180205; cv=none;
        d=google.com; s=arc-20160816;
        b=spvn+5kPJ9tuMGuHe7mDknqiYiEyXbn44RDaM9hZdGqnH7IsAVDM5IQfsXjik6uwpM
         paK9on4a8rCliiFETTUJm82Ffb6iAwuNnuWsPwqBLxNTy9gAtUgfcvc0aoWSVDQmi0+m
         9Zx7oMZu0iK+X1PTL4Ly3k/t1twQWMKqUH+XkEgrUMKOJgh52edAXbplKafujWh5z4JF
         muzO5ZSo29+KS08/OflHJEer1fdBby1VAcIIe8qtQXqJ0Nxlg3BRE+G0uJgqyuH7qiYi
         +i7c33oL0hAp49GR+Ok2xnE1TpiNPdipZ3Ei9a1tOmYIl07LFMwbWPDlTAQEebBe0WTc
         gxSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gXb/hya9MuzyVUKh4KO8Jgkudhwo0tzYCFb8lkCPFT8=;
        fh=2uZ6GlhQQTY2ahmzc2c54mxo9ZMihAjp9lBkYEzVmc4=;
        b=M1vNd43lhFmKiWH6uwYUfRpH9wkcVeKzwAJsVVRQ5WIMuWx9WBif0suDMZaRckWmDp
         pfS6UrA+i671wtXI+eh5gisOBuaiPr6mjnOEwnAU8oz41VwtwyGz13AQEb/s/r/yNIfF
         9HOlGbWU5ZCdB18CYvvntNldKiMKObq0Fm3g+l+P4D29Thi4fRkmxHdZDscQcKp1XCXx
         OMpvbJpGr2U4wS2q2gJxf7RJpa0HEA/Xo8eYrcQiMbKdzV0ShkXWpCITE8N85+00zvsD
         4rQBW5RNpqRiJFZ2EPvC2wsiVRQXvQCTZ13WeuNqFap1fhAUEDKL2EHn0y+OPn/gYHLk
         qpsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mkLzpioX;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id u2-20020a0cee82000000b0069694f92763si813177qvr.4.2024.04.03.14.36.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Apr 2024 14:36:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-6ea838bf357so259235b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 03 Apr 2024 14:36:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU0s69Ag2z62cvdZ9tgnt2kMbyyKak9i4daPlyCEvBplwHapDkniWx++YD9A88XAPY9LxAdKjVUkgEBMfKdTJKdItU97JeAH1ABFQ==
X-Received: by 2002:a05:6a20:9151:b0:1a3:adc3:ce29 with SMTP id x17-20020a056a20915100b001a3adc3ce29mr1090942pzc.15.1712180204577;
        Wed, 03 Apr 2024 14:36:44 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id j5-20020aa783c5000000b006eac81fa1fbsm12273046pfn.66.2024.04.03.14.36.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 14:36:44 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: linux-kernel@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Arnd Bergmann <arnd@kernel.org>
Cc: Kees Cook <keescook@chromium.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Subject: Re: (subset) [PATCH 02/34] ubsan: fix unused variable warning in test module
Date: Wed,  3 Apr 2024 14:36:37 -0700
Message-Id: <171218019557.1345248.1235044277725212529.b4-ty@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240403080702.3509288-3-arnd@kernel.org>
References: <20240403080702.3509288-1-arnd@kernel.org> <20240403080702.3509288-3-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=mkLzpioX;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c
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

On Wed, 03 Apr 2024 10:06:20 +0200, Arnd Bergmann wrote:
> This is one of the drivers with an unused variable that is marked 'const'.
> Adding a __used annotation here avoids the warning and lets us enable
> the option by default:
> 
> lib/test_ubsan.c:137:28: error: unused variable 'skip_ubsan_array' [-Werror,-Wunused-const-variable]
> 
> 
> [...]

Applied to for-next/hardening, thanks!

[02/34] ubsan: fix unused variable warning in test module
        https://git.kernel.org/kees/c/bbda3ba626b9

Take care,

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/171218019557.1345248.1235044277725212529.b4-ty%40chromium.org.
