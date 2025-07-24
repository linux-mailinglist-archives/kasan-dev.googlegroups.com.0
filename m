Return-Path: <kasan-dev+bncBDOJ7K5MW4NBB4PARDCAMGQE4WKQD2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FF9AB10AEE
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 15:09:06 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-45624f0be48sf5341015e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 06:09:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753362546; cv=pass;
        d=google.com; s=arc-20240605;
        b=itRgQBdKgXldTdT4EdGf/bVqLmNCNz7mzS2T0xW9A8rQdK0l3DDYVlS/9ICRmhfgwI
         AF3bNq5F85FEJ9+8H0M5IdSKDiXTg1DHNPsH3g3liptAg6qoZQZE8HngL/G86ieM0TvD
         WSvn/3ZTNSzehLc2By1hTKEXHKnPm9xNM/AbdwCkaoBkAOiQm8t+IGjIB7jkVYhuucQz
         cLLyEXtDnF784f7BK2ahZI5Ni5oZFZWOovD/Uh+tgacandoxecb4Oy0U42I7dj7fOkmh
         izP8HSVnuq/A33KRRtm0Qrbt/PlLuGHPCHMMns93rQY+3mccV/Dm9lyB4r0blPo6Fj8o
         DF4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=uK6A31UkOJ9554jHSyNcJCZ9tJJ9maI0Yl38f0J5zbo=;
        fh=0eSaCkXkP77he/iUz4tpI+DTqxnjDl0TVONr9WDYFQU=;
        b=fmXW/21aY6aUhwbJrob+MVANiUhmqt0j3WyuuS2zHSerO0aDkNwvOFZlxY3OD3FR56
         bqRoaeigMk/OQhOUgPIYmGTYPkjybTuOrk9WmF+h4aqR/SfaFDGdvb0y6CiTb0dC9HPM
         HY8BFeRcfm0JY5hnOjOUCUS7mgAebbGFFU658FgDRj3HQPDfcmazNx12wJUcPH9OtMhz
         dptCww3rY9rWomj/vt5hXdM7BARG2H7GrZtj+Bk1ypSQXe2Wn54I5+j/q0GzrKXtyb5D
         vA07ONUr3VY7elc5gtkqRM9fqHfjR+n2GK/yaZD6E15G9ffBt+eF2eVHNe1zh2ujPqt+
         zLEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of n.schier@avm.de designates 2001:bf0:244:244::94 as permitted sender) smtp.mailfrom=n.schier@avm.de;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753362546; x=1753967346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uK6A31UkOJ9554jHSyNcJCZ9tJJ9maI0Yl38f0J5zbo=;
        b=PdkaKOVsPcQtQ0CfgnwiuWeMoMj9Jn8VWRo4+GuimuFRcLKMDVDCQJHR67SXrcpe54
         sQKGDtmdeQ2FbiaafiR7hrTHrry3jIOdiu7h4IZLfwkpeY/A51rluwcFD6oOTz4XpzsF
         DDTATrEZqnn2SP7NFj3AHF/sSKz0D+FYC/07TdjWvJ7Iv9kf33GddVBa17Sft+mL0Haz
         CGOaJ4VzonXdtWUA2tMFudYApn5Y6kq003LiVg/M+GHCPvx4G7w8eCBBpqYBV1hf+LU5
         U6NKt3ClfqG0kRr2PLTpnxKiWV0aoHj+kylV/XlayAbVR1xBo18U2qW8uMLsmKxWXEjg
         IFtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753362546; x=1753967346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=uK6A31UkOJ9554jHSyNcJCZ9tJJ9maI0Yl38f0J5zbo=;
        b=NOtlvB1BthN8j4U8Swy28W9YmypMFSdUQ6pkQPl7ot6+WdXMd2AG36pNPcOAOuxbxm
         KU5hBSI9m46bZ79gAVHyyay47JP24pE/SHWjWMT6sSDNOiWibmU3xMh4xNs72RFzQ1h/
         UWFJB5rN6WTFQ/ERyZOkqThXcTGHCgxTHvLox3kut4y/+JItZD7zwZXHl0CEYmcXFHzb
         zkB6VW7ns2SwaV9OfJFeam9I4RxaOKvmYO0O0fGxdaEt8TWjoPKtfcvLiU7mVRjSNt7P
         ZaQCk/K7AJn7W0/EK9q7KGZijyoXGTwd4QrHhMSexStMKUXhYEqu+AIaAqhTGJtVWUBk
         9BPA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCcA/O4sWMSv3gZCgagD6aPD69DtSA6F2VI4eP2BrF8bMp/4yz0hQpvjDhDoKbKo+YC7mJ5w==@lfdr.de
X-Gm-Message-State: AOJu0Yy4gd/oR/fM3aQ33FYQlE9/GOXmr/LAwKtpq4UUuKnogUnnpt2+
	rBKHHekOULW7SElZvPkFU0vad68rhCuYrBP3GWGz8nrcRwravaBNhi8s
X-Google-Smtp-Source: AGHT+IFgoh/YUVTQnRPlKULkQNWEE2nHqDFgujFEE15MXUT4VxNXJmmqHODdG2MeyNxhaDN5TrG7LQ==
X-Received: by 2002:a05:600c:3508:b0:453:1058:f8c1 with SMTP id 5b1f17b1804b1-45868c91d37mr68703675e9.3.1753362545631;
        Thu, 24 Jul 2025 06:09:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfzatuMX3RQIz9hYkIWJ2DYN/Jbip3Iwc6k20p3bBJZbQ==
Received: by 2002:a05:6000:230f:b0:3b6:db:74a4 with SMTP id
 ffacd0b85a97d-3b76e3a2b6cls532377f8f.1.-pod-prod-01-eu; Thu, 24 Jul 2025
 06:09:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4fogivF6MIF3qMuuaNjP3hhdLTLfEgRyxMjgNddO8WHXsuNijU68+ELkSppAczo0Yu56gVU8/xCQ=@googlegroups.com
X-Received: by 2002:a05:6000:4382:b0:3a5:8a68:b82d with SMTP id ffacd0b85a97d-3b768f079fdmr5638633f8f.43.1753362542844;
        Thu, 24 Jul 2025 06:09:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753362542; cv=none;
        d=google.com; s=arc-20240605;
        b=hLEiXQzpuf3ox4BC4VpMk8XCbKOvDpwCKDZdJsqrBCjc1wqfymRIOetbeFxu2uViti
         glXBcbmsO3f1X5sUf8pN1wKhSgfRUURNK8jEwFhX+Xpy3ppKpBa41ZrklCJ9Z/lisMme
         VV6he4NTQ90e2zCGJgT1zIedw2r1Csj2VvgW9xwpYKif0ige+ni7ZldC+YaOf7CVflkP
         3nsXrUYrxCZMfrzNVv7xAzuVLtxqPrlvjFRVoGSMmj/iiXact0tBXLvZqJz2Pupeqlc5
         2eERCrm6acC3WWQkIrIylZpfAkmmESe1Ab6PcPV/LA7Fw2QwOwWraaiL3oWgqOCxtbei
         fVtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=ne/XcgrgO/KJ5Vpn5Kmd1KTfFMh8OZxebN5iFuDYEM8=;
        fh=sebxw58xt0y4s5SaxJDWkCmSkCD1kOXKpZtUwp1jNdw=;
        b=kJhifiXLCVvzRc4Sa8Npd/ZBu4PQlTT5gakgr9NL4MqobAkP0Rrfo5dblLJVjtk3hF
         U0x6dB/1iUgHz7mZCmQ2K3mhkiOwF+tIhg6dl9+hs8gUQNXKIbfP/MF6j29f5ppRLrlU
         DfQXWc+3l7NimbLJv3IYOn/CO8fPkjQyOsDBjUig3T8iyuMeV+2JYlBOpX1uu+hi6nSC
         8E2Qyije/PtnbvpUNDmZLAeDPOYE0bIIlTFcdPVSYvgvwInlYnQQDo4epW5OvSvN54mJ
         K7toTQZWti6BgSjlY+hcE4DqbOd1wWD1ZE33txZFd/zL3baO9XNQr2B3SdoxiZVcAhnm
         2v+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of n.schier@avm.de designates 2001:bf0:244:244::94 as permitted sender) smtp.mailfrom=n.schier@avm.de;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from mail.avm.de (mail.avm.de. [2001:bf0:244:244::94])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b76fc91401si37826f8f.1.2025.07.24.06.09.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 24 Jul 2025 06:09:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of n.schier@avm.de designates 2001:bf0:244:244::94 as permitted sender) client-ip=2001:bf0:244:244::94;
Received: from [2001:bf0:244:244::71] (helo=mail.avm.de)
	by mail.avm.de with ESMTP (eXpurgate 4.53.4)
	(envelope-from <n.schier@avm.de>)
	id 6882306e-1808-7f0000032729-7f00000189dc-1
	for <multiple-recipients>; Thu, 24 Jul 2025 15:09:02 +0200
Received: from mail-auth.avm.de (dovecot-mx-01.avm.de [IPv6:2001:bf0:244:244::71])
	by mail.avm.de (Postfix) with ESMTPS;
	Thu, 24 Jul 2025 15:09:02 +0200 (CEST)
Received: from buildd.core.avm.de (buildd-sv-01.avm.de [172.16.0.225])
	by mail-auth.avm.de (Postfix) with ESMTPA id 0973680A49;
	Thu, 24 Jul 2025 15:09:02 +0200 (CEST)
Received: from l-nschier-aarch64.ads.avm.de (unknown [IPv6:fde4:4c1b:acd5:6472::1])
	by buildd.core.avm.de (Postfix) with ESMTPS id 6DAEF184464;
	Thu, 24 Jul 2025 15:09:00 +0200 (CEST)
Date: Thu, 24 Jul 2025 15:08:58 +0200
From: Nicolas Schier <nicolas.schier@linux.dev>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Paolo Bonzini <pbonzini@redhat.com>,
	Mike Rapoport <rppt@kernel.org>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hansg@kernel.org>,
	Ilpo =?utf-8?B?SsOkcnZpbmVu?= <ilpo.jarvinen@linux.intel.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>,
	Michal Wilczynski <michal.wilczynski@intel.com>,
	Juergen Gross <jgross@suse.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	"Kirill A. Shutemov" <kas@kernel.org>,
	Roger Pau Monne <roger.pau@citrix.com>,
	David Woodhouse <dwmw@amazon.co.uk>,
	Usama Arif <usama.arif@bytedance.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Thomas Huth <thuth@redhat.com>, Brian Gerst <brgerst@gmail.com>,
	Hou Wenlong <houwenlong.hwl@antgroup.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Andy Lutomirski <luto@kernel.org>, Baoquan He <bhe@redhat.com>,
	Alexander Graf <graf@amazon.com>,
	Changyuan Lyu <changyuanl@google.com>,
	Paul Moore <paul@paul-moore.com>, James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Jan Beulich <jbeulich@suse.com>, Boqun Feng <boqun.feng@gmail.com>,
	Viresh Kumar <viresh.kumar@linaro.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Bibo Mao <maobibo@loongson.cn>, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, x86@kernel.org,
	kvm@vger.kernel.org, ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org, linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-mm@kvack.org, kexec@lists.infradead.org,
	linux-security-module@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v4 4/4] kstack_erase: Support Clang stack depth tracking
Message-ID: <20250724-optimistic-armadillo-of-joviality-e59222@l-nschier-aarch64>
References: <20250724054419.it.405-kees@kernel.org>
 <20250724055029.3623499-4-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250724055029.3623499-4-kees@kernel.org>
Organization: AVM GmbH
X-purgate-ID: 149429::1753362542-BED92A7D-5329B415/0/0
X-purgate-type: clean
X-purgate-size: 870
X-purgate-Ad: Categorized by eleven eXpurgate (R) https://www.eleven.de
X-purgate: This mail is considered clean (visit https://www.eleven.de for further information)
X-purgate: clean
X-Original-Sender: n.schier@avm.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of n.schier@avm.de designates 2001:bf0:244:244::94 as
 permitted sender) smtp.mailfrom=n.schier@avm.de;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, Jul 23, 2025 at 10:50:28PM -0700, Kees Cook wrote:
> Wire up CONFIG_KSTACK_ERASE to Clang 21's new stack depth tracking
> callback[1] option.
> 
> Link: https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-stack-depth [1]
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Arnd Bergmann <arnd@arndb.de>
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas.schier@linux.dev>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Ard Biesheuvel <ardb@kernel.org>
> Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
> Cc: <linux-kbuild@vger.kernel.org>
> Cc: <kasan-dev@googlegroups.com>
> Cc: <linux-hardening@vger.kernel.org>
> ---

Acked-by: Nicolas Schier <n.schier@avm.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250724-optimistic-armadillo-of-joviality-e59222%40l-nschier-aarch64.
