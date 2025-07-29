Return-Path: <kasan-dev+bncBDZMFEH3WYFBBO4MULCAMGQEQHOZBTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E7CCB14A17
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 10:29:03 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4ab844acca0sf121279921cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 01:29:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753777723; cv=pass;
        d=google.com; s=arc-20240605;
        b=HCUFK9kWGcDSlrm7HzqTCppiE+UaCytGrvZfiTs0ui2DWsK9H4yWwf34hSXD3dYjdC
         +jEkuP7yfk/S21f/lqIs9gsWEgaFZXb1waRRK6CUs+8S1MTPHkKf6EK845zA0AXNiX+i
         Mw0PJd/stZeoxJ2QFrrXQm5YVdzTr41OoZZ6lbGSA8vRvPbqCLMc/BP3HJrMfMWxwRpp
         QZGqJGemG6IYU63lhZk5t/frD7J1iY4T3l5zHI3KPIT/MMLs+3K3rWxu3ps4hquSDF2R
         Om1e+I6GeesmXsHF+4jtH4ZLocgpktoKVob5WuD0b6yNWiRenyDwjGmj17Vm7psm3+J9
         Ltig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=WBCTMvNs5O/f+mXDtvNtOB8nb9WorX+gt/nvpz4whh4=;
        fh=sFAWf/9Pp9eSBjvEMZeqDUN6APM2N3bxpDdsHEgZL7w=;
        b=MRmf6Xj19s3SNB4RVdnE4yyHzKS2xDiVsdKpvHB/IbGLxIr+kqdmxvvJMR2eOi2t3r
         /tN7bWTq8brVz/7yH4fhC2D1+TS9SCrYf4rQorWXvZzSRWkASIP8tAF1O4Sn+P3VM4Nz
         K5ArNT9uu4IAi/BKNxWTt9NjOHoFH47sSO3b1vjDx5q1d4fhZCfGnftGGUX7hRUBTxqd
         i8zWeXBH5XFxiqqHNX5nZe9N8QxkzPa44cqLUU8NK/MNzZVVHx3ZpIgENSyHTOjcWcQt
         CxFklGBdttjE8pOsWWCM5zFT6CuwGrhoPOC1qTMQ+gAeBFQG6JRrJUPEgrUIMcMYKHFc
         9Omw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XKsDX+KR;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753777723; x=1754382523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=WBCTMvNs5O/f+mXDtvNtOB8nb9WorX+gt/nvpz4whh4=;
        b=FjpUjWnuv7PIIAL5VpHVkJLx1Fe2Vi73r/ntmJS9qrykbjooAuewHXp4SM9zDlMWhe
         kqojTlPRFoJFi7hEhwWGVMNNipr7ziUJFOUDDAljCkWF4k8lx4/Zvsh5vtBdc+tPHTP9
         JcH8k2wCqdQH5n/qYVq6HNb00y03+ohmcv8RQpkfCcT316uSsLerNPoHswI1bpb0ozt+
         +pBnagT3uuhloZYFLDKq3sNxIyiSeXQLmoGRP0Mak7UP3CFE89cKRuOef9PVxrs+o9B/
         i+gd521gAZjcTuUvkeDy0DYP5GtHrSzyqZw/qgTrEBbkTSKSkRX+KVPpUXLwzbdrp47J
         5xow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753777723; x=1754382523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WBCTMvNs5O/f+mXDtvNtOB8nb9WorX+gt/nvpz4whh4=;
        b=uFY+lnaX/NMOApggLNOrsN/Ch0SYsreIeqrO6/F8OJaEjBwlWQNveLLtOJDxdeMhyw
         erKYbM6t4WmkWwyNEwix4Lpt+Pgmp+Rskza8Muyy2S8v6ChFGzjyMho/t1bPSPezBsKx
         D9GjkhDbPOSMduURLH4scbSgCOZWWR0Qg89w2txg4r30PvDSmt2JDDQqg+yWC0XZQUOa
         cUYX2+gGwtehVkgIQDv92qYe+du/06X/H90DnhHVH6ywonr3F6t2ZmWqA0BAJbdv/zYi
         xHpxDr4H46XjlnyV4hkhn4lPU5VeuLKp+vZntwDUH2pzSzPe1nlQnKRkO+2YoCWDZ60g
         pBYw==
X-Forwarded-Encrypted: i=2; AJvYcCWurvATcs7SX/RXaJfA2AJnBIC2sB6Fnc9EIjDPkm3y2UviEuBeDoRYiNCrHKTcwd2gqHR5Ng==@lfdr.de
X-Gm-Message-State: AOJu0YzWlPpQ3wNEqjSCcuZFuiPRLHVKz33/3L3M0yHnby0KmWPqFrbW
	3qDCxSeHDCjwSu7896VXb7o7vzVZwzeJlX3Qv57eecDORIibEnHp9sTs
X-Google-Smtp-Source: AGHT+IHMkTXbPoqG2UJvP5wBmyyt7lYuBXJArBN1qVALT++0AvLOXyDVQqgPThWFXv8AVJ58Jxu21g==
X-Received: by 2002:a05:622a:164d:b0:4ab:37bd:5aa7 with SMTP id d75a77b69052e-4ae8eff1182mr205122371cf.24.1753777723485;
        Tue, 29 Jul 2025 01:28:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeKISxLc8KbHVUWBOY8MDl5Gi0XhWY5gUIAVMUb/xHQAQ==
Received: by 2002:a05:622a:1451:b0:4ab:9d76:f985 with SMTP id
 d75a77b69052e-4ae7d29b383ls84308021cf.2.-pod-prod-09-us; Tue, 29 Jul 2025
 01:28:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjRBO0Tvn4eDj/K+HZkZ84isEDjfF+0PgkJOohOIDtyHytYralTc/fsbfHkdBn/DhBIaNagz2qhl4=@googlegroups.com
X-Received: by 2002:ae9:c11a:0:b0:7e2:ebb0:8d6c with SMTP id af79cd13be357-7e63c1b2f11mr1599695485a.56.1753777722371;
        Tue, 29 Jul 2025 01:28:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753777722; cv=none;
        d=google.com; s=arc-20240605;
        b=C1R7q8VYfx27Gq3KdwrSxepDCBDjEaae8Hcu+w8NKKM7+rsTQB9/WqmqQP8zvvl85X
         V/I6nYhTjEH3fxXZzvaW9VmSZBMroN48t0mhyDtcRIvpZ47ZA4gq+N6kb03iAn6kBHol
         0AMZXOXdrUkLw0ZEIjZXvFoxvAXAsLWAxqz+hvSFpvOWOpGgB3sAkObsU3kSbgmlcHRT
         TgIKctTuNytmB8fgHkhgpK9zhD4nWpWoNleFkAVuqJd6740Kwa5n6YJKoLZIUpdvdQWH
         12ALflK8i6k5IgE13f5T5GBHmT1+qYr7/AgQ5nBE+eWK5+pqjXxDaB1DjfuPMGFzkIVu
         9xzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=n85pmn0u6Z+c4iXgUXsS+36jAK4nq/BZyup+CKlkXI4=;
        fh=jnB81W/qUSXDU4aGF3/Y1/71PSlHukvuaH3yOdBYczQ=;
        b=EcJ784vj/UCujXvcLTu2qoXKCK311XSzywErk/uQmZVfCF22BtHN5osC+oB4qb/nQD
         U1emAv9u2MczcwDCC6OEKoiuEgF3tnWVW3fpnTEFiuJikKxSg4FJjUmUsZf96aPzEWou
         6kY7ZxCITEjswiqKbVEtxLsJzJx8pJqmKQm82crubMmmHFEkh/Vs3fxs7MhS1QA2+cmR
         a1FOzzGxQFw7mNirteF6A4fe7JpeuRdm3tkCBVihEgfLD4Da9XgWX9VH0t+ms0lxs0/Z
         vS9GxpFM3dy/vXseyRnUX4lJgenE/n75vTC7bEw/+qH7VzhpoVAb22xC+i+eIkuqoptT
         sJyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XKsDX+KR;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e64329a427si46012285a.2.2025.07.29.01.28.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Jul 2025 01:28:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 90E9A5C5B7A;
	Tue, 29 Jul 2025 08:28:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0D23CC4CEEF;
	Tue, 29 Jul 2025 08:28:17 +0000 (UTC)
Date: Tue, 29 Jul 2025 11:28:14 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Paolo Bonzini <pbonzini@redhat.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hdegoede@redhat.com>,
	Ilpo =?iso-8859-1?Q?J=E4rvinen?= <ilpo.jarvinen@linux.intel.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>,
	Michal Wilczynski <michal.wilczynski@intel.com>,
	Juergen Gross <jgross@suse.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Roger Pau Monne <roger.pau@citrix.com>,
	David Woodhouse <dwmw@amazon.co.uk>,
	Usama Arif <usama.arif@bytedance.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Thomas Huth <thuth@redhat.com>, Brian Gerst <brgerst@gmail.com>,
	kvm@vger.kernel.org, ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org, linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-mm@kvack.org, Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Hans de Goede <hansg@kernel.org>,
	"Kirill A. Shutemov" <kas@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Hou Wenlong <houwenlong.hwl@antgroup.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
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
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org, linux-hardening@vger.kernel.org,
	kexec@lists.infradead.org, linux-security-module@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v4 2/4] x86: Handle KCOV __init vs inline mismatches
Message-ID: <aIiGHmw8IJb9vsM5@kernel.org>
References: <20250724054419.it.405-kees@kernel.org>
 <20250724055029.3623499-2-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250724055029.3623499-2-kees@kernel.org>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XKsDX+KR;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Wed, Jul 23, 2025 at 10:50:26PM -0700, Kees Cook wrote:
> GCC appears to have kind of fragile inlining heuristics, in the
> sense that it can change whether or not it inlines something based on
> optimizations. It looks like the kcov instrumentation being added (or in
> this case, removed) from a function changes the optimization results,
> and some functions marked "inline" are _not_ inlined. In that case,
> we end up with __init code calling a function not marked __init, and we
> get the build warnings I'm trying to eliminate in the coming patch that
> adds __no_sanitize_coverage to __init functions:
> 
> WARNING: modpost: vmlinux: section mismatch in reference: xbc_exit+0x8 (section: .text.unlikely) -> _xbc_exit (section: .init.text)
> WARNING: modpost: vmlinux: section mismatch in reference: real_mode_size_needed+0x15 (section: .text.unlikely) -> real_mode_blob_end (section: .init.data)
> WARNING: modpost: vmlinux: section mismatch in reference: __set_percpu_decrypted+0x16 (section: .text.unlikely) -> early_set_memory_decrypted (section: .init.text)
> WARNING: modpost: vmlinux: section mismatch in reference: memblock_alloc_from+0x26 (section: .text.unlikely) -> memblock_alloc_try_nid (section: .init.text)
> WARNING: modpost: vmlinux: section mismatch in reference: acpi_arch_set_root_pointer+0xc (section: .text.unlikely) -> x86_init (section: .init.data)
> WARNING: modpost: vmlinux: section mismatch in reference: acpi_arch_get_root_pointer+0x8 (section: .text.unlikely) -> x86_init (section: .init.data)
> WARNING: modpost: vmlinux: section mismatch in reference: efi_config_table_is_usable+0x16 (section: .text.unlikely) -> xen_efi_config_table_is_usable (section: .init.text)
> 
> This problem is somewhat fragile (though using either __always_inline
> or __init will deterministically solve it), but we've tripped over
> this before with GCC and the solution has usually been to just use
> __always_inline and move on.
> 
> For x86 this means forcing several functions to be inline with
> __always_inline.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>

For memblock bit:

Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aIiGHmw8IJb9vsM5%40kernel.org.
