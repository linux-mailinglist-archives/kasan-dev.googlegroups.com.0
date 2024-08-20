Return-Path: <kasan-dev+bncBDI7FD5TRANRBRHGSO3AMGQEPP2NF2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 32F64958EC5
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 21:49:26 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-39d2ceca837sf48745685ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 12:49:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724183365; cv=pass;
        d=google.com; s=arc-20160816;
        b=Or4Y/cr9cH64zjnSi3ubYvBkNBIPUhv1AI+xKgnqnazM/QhHW/QuUFmmXUumD9PhKH
         O1P8dLq8VQ6X1F4pqqicQ3HJCIKc+eZuGvA4Om5l81x85BOHU+0ZTfy3yzjmg8vkYy/7
         RgSnQwAs44mg7El7VbauMiCes3/du2b8wrHToGtk93IOLHm1xEFBuvjXM69bd9t8bkof
         S1LK1RSwZ7B/8LQtfBVecLt9/riM2Vum5ZWkTeWZrd6JzsrEZVCoIlRGzii5+Kr6zhch
         M+4IUGQuJWb6uzhLRrHNp17C4kopvvMqEEWpJYeq3qhZnpwF/sjzKF9fOqnMtp/eg9Ed
         w06A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=vrAeFQXGxWnt92b0HQmoY+Zl/1c5IhGSi1zKDWqI7wM=;
        fh=n8/zFiqJxEk6A2Xe0cD07PVkr/KhxrmEjUjcBXX3/KY=;
        b=Mo+cg0qOo3xoj6eYFeWlWRmJzD6zPiwJhvUbi7ApF7IPvTLpwqYV7yUppNwu+BoCCO
         VaAKOYpJADuUlxpgrh8zxB+ghCl1KqeJ7T4RGpy7FhvWU6AigRv4GQgbPi7qS3ZVs4hZ
         mhpk/JwUYiYqt+IXeh0V6gTqnqr58U/Ku3gcJzFmedw5zHh2Unwme3luJFTsslwxvUdU
         8b30Z3BFsp4rgJeg4TzM5Km9sJhQJ8SeB2UclnaebBIJicoTE2DcikzN8K7OYiF0zQjR
         HNcBJ8NLuFwI1dq4oF47H3Nuh2UDXb7ffZpZABZfTusZ8sgBM1gghr6VviyZIDdndiRJ
         92gA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="0u/Mp7hu";
       spf=pass (google.com: domain of 3qvpezgckcxkjjxrobodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QvPEZgcKCXkjjXrobodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724183365; x=1724788165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vrAeFQXGxWnt92b0HQmoY+Zl/1c5IhGSi1zKDWqI7wM=;
        b=qiO2jlxkIdYAGliOhFlb3mIJDYaUbmpeWsN+62aBc5onl70S1nVnJ2/uOH+5eMywGb
         iehd2bWQkZ/7DHwix4LJPZDEeP3vQDdY5ogIglTx0IcRChyHMFqTaQbN8Exq6pidTLsw
         5e79KEMbaikouvxlQWqn/0gDqD2pZqexD9TJtKn0xJ/zgNFSF3dcB0LvF6S6rSHJpZBC
         zq0unKZb/BuwLHBgY1sWYDNZpAlr7enMCii2lQx6Vh8mVPPCSEM6gqACKCLGsogn+1eP
         ohBj0dC+QQ72zDn9HySB75Wa6DzPJ1pahZutF6oGplYW15nrRSuG+GIOfPVwDbjc5kor
         2qOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724183365; x=1724788165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vrAeFQXGxWnt92b0HQmoY+Zl/1c5IhGSi1zKDWqI7wM=;
        b=L4ngHpkXWDkS6CRvWysr9dOGdCmdMqUfxy/ouWIvrpYuiulBizTZ/cMIggBSzdDimT
         aDKI+xAz1ufIu8CaDb0dJM4z8K4Z+QjwFHl/WKjRhSXPb7T8a/UDqYSU8HR7NMdHrBCz
         ERzd/5F9C18HgXZdDBB7Q0l42lHFPEgzzglNObpKzs52YJevCKZCzw2scbMlS8tBftYj
         i1N7oHis6WsPhEXTeJtlcwjMswA54K7TO36qlRu00ETT25kBdwf9r9vtP+4FQ8KyTMcK
         eTQEOv4s76QJIvjQBPiwvnV2nYYaho936Td0PG+VRrbZQXuhF9+P1fHpIFla+MRzxr1s
         XZvQ==
X-Forwarded-Encrypted: i=2; AJvYcCXPgqoDdQ/kbbGftM5pL1+EcOvRoHPrLULXosCaf9U7kI0Y5RKDUiESEFED5o8goDBVhrPE9Q==@lfdr.de
X-Gm-Message-State: AOJu0Yzjiy+OjagrNsROqxXwiPxM5/TvpWCW5zv2PuZkod+MJ3dE7YEM
	S/6xXLBeGB/PhBb5bA43qas94YGFyf0l4R5+d5B1wIyZDbGl3rKj
X-Google-Smtp-Source: AGHT+IHrW7crhhyBfiWjD4zBpRIO41A9thec2ZitKJXzF6GugHN3TQP+fJfflSbWpAX3rCd1j2Xv0Q==
X-Received: by 2002:a05:6e02:20cc:b0:39d:47fe:85e5 with SMTP id e9e14a558f8ab-39d6c35964bmr424435ab.11.1724183364724;
        Tue, 20 Aug 2024 12:49:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d0e:b0:39d:28a7:b109 with SMTP id
 e9e14a558f8ab-39d28a7b4e5ls22560065ab.2.-pod-prod-08-us; Tue, 20 Aug 2024
 12:49:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcvibUokIHjkFjToQyJgmJ7sJbuE8dQPUUvWa3GKV7jNWKkKDUye2FbOojoYqVv7nXe6qMIxicJX8=@googlegroups.com
X-Received: by 2002:a05:6602:2cca:b0:822:3d11:106b with SMTP id ca18e2360f4ac-8252f2fa456mr68645539f.1.1724183362969;
        Tue, 20 Aug 2024 12:49:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724183362; cv=none;
        d=google.com; s=arc-20160816;
        b=T5g0Pfp2Zd7N3juNGUZGEv6gYpZOc/b0kjxujOYhAEGixC7UuJsAPv3DZhMji9LeN0
         0n+3FBcBoidkafK9479TLRRvKsqOuvTZfQxFLPnFxoG8pO9IP/usundtw02C3Pnlanjc
         /auhK/VEt6IdxL66nhXhMYw7TxmpmMdNp8VKFzc8VB6HOt+xiGodW82mnM9lLktgUhmC
         LSUmNjybtSzCz0PlsmyuCkNvs/OTPR+YEc76IuaXoYiOrq+D+cFkoLFKanFvriGWmb7w
         Wd+Aiy5PHnPT34yZUsShilywIGfSnf0GTPw1PKqprP4rUSU4XSHokmVCH6Dfp76C5Xv+
         n8Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nhd4bVGt7t2cMFreV83ln0lve5lvedn9wm7Lt/YZotw=;
        fh=zb+XmoHd5iUALxtTEB5lrdMaH+O+Og3P+Xylq2OheYU=;
        b=xWLP3hUfcjDvX7oeo7jgStt3fsWBEqCA/9wgo+f1IS8rzNS2tL/JdjfCFmZPqPd57Z
         DX46DGEuDYapbTZ9TXdEmnO4YGXNVLqDD2naPcfCAmzyiK92lzJesrPHaQOa8uQSX7LA
         oz1RJdos7ZhuQl/Mysc7p+yO6f3H7098YzlyrjInY45Hzoyuwf5vEfRLfUN/H9r9/8xq
         W5V+If8VTceJC1LQcI7yyIWKOCPUxMbzA8jwIiJUD1iTfXCx+z1dznGelBOMzwK5GjIx
         6f7Ny6pZK+0fUVzjB7r1ITKrJb8FDyjYf04Xh8m/Uv1/HErY6G60p0DkoV0T05vZY5JG
         rNvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="0u/Mp7hu";
       spf=pass (google.com: domain of 3qvpezgckcxkjjxrobodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QvPEZgcKCXkjjXrobodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-824e9b4ca3csi47630439f.2.2024.08.20.12.49.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 12:49:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qvpezgckcxkjjxrobodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-e11703f1368so8190465276.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 12:49:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXwT8lv3B8sSu0cnwJ8gmFBzlFGmM1aHShiFYNRgoL65BfXAZkvzjC1WbeAKMaYJbwUWn7Mup7Lc3k=@googlegroups.com
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a25:9744:0:b0:e11:5e87:aab with SMTP id
 3f1490d57ef6-e1665542f69mr767276.10.1724183362312; Tue, 20 Aug 2024 12:49:22
 -0700 (PDT)
Date: Tue, 20 Aug 2024 19:48:57 +0000
In-Reply-To: <20240820194910.187826-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.184.g6999bdac58-goog
Message-ID: <20240820194910.187826-3-mmaurer@google.com>
Subject: [PATCH v4 2/4] rust: kasan: Rust does not support KHWASAN
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: andreyknvl@gmail.com, ojeda@kernel.org, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Petr Mladek <pmladek@suse.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Yoann Congal <yoann.congal@smile.fr>, 
	Kees Cook <keescook@chromium.org>, Randy Dunlap <rdunlap@infradead.org>, 
	Andrea Parri <parri.andrea@gmail.com>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	Vincent Guittot <vincent.guittot@linaro.org>
Cc: dvyukov@google.com, aliceryhl@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	ryabinin.a.a@gmail.com, Matthew Maurer <mmaurer@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="0u/Mp7hu";       spf=pass
 (google.com: domain of 3qvpezgckcxkjjxrobodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QvPEZgcKCXkjjXrobodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Matthew Maurer <mmaurer@google.com>
Reply-To: Matthew Maurer <mmaurer@google.com>
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

Rust does not yet have support for software tags. Prevent RUST from
being selected if KASAN_SW_TAGS is enabled.

Signed-off-by: Matthew Maurer <mmaurer@google.com>
---
 init/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/init/Kconfig b/init/Kconfig
index 72404c1f2157..a8c3a289895e 100644
--- a/init/Kconfig
+++ b/init/Kconfig
@@ -1907,6 +1907,7 @@ config RUST
 	depends on !GCC_PLUGINS
 	depends on !RANDSTRUCT
 	depends on !DEBUG_INFO_BTF || PAHOLE_HAS_LANG_EXCLUDE
+	depends on !KASAN_SW_TAGS
 	help
 	  Enables Rust support in the kernel.
 
-- 
2.46.0.184.g6999bdac58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240820194910.187826-3-mmaurer%40google.com.
