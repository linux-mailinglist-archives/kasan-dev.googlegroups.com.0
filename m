Return-Path: <kasan-dev+bncBC7OD3FKWUERBL6VYOPAMGQEZWX6ABA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 53C2667ABFA
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:39:13 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id u2-20020a17090341c200b00192bc565119sf10427670ple.16
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:39:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635952; cv=pass;
        d=google.com; s=arc-20160816;
        b=t0d5tZzcopRp9iFJeB7/OhXwpShEqMCA1iwXavKH3lPdEBmXvxv9bkPnFoob/vfvAL
         QFjAsqhYYgY5cXz+bZL8bYiylx9/0o+31+UaKyPQoEZjCNICMYZxpZCU4nW+KXQnDNWt
         8Q8w1IGbjlWkhOZrNO/hmEuXkkCNWEUGAW6Q1jbk9pTbzbIU+EVdsOFc0ZZB/g7n9iCL
         ggkWG3tCCEpccHBZx8tng61bQfYGuiEOqskJnZsrrHK0zCOZBkgx7lpX4O9fS5EqGN6F
         Z0R8ywuY1d4j1jcTfey5o0/BzJcAn53E8tuP+7DHvwGGcz2qJ4h/ygY7GhG+5rqshxxD
         SVrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=tNi6c24ibFtAn5AWfkDlI9d0bSXlCMxdJnW3OQAyW18=;
        b=yiauRNV4Epw5iM1EaF6ho8baXNU1WsuGk1Xd+Zm+j78MO6HUz9j+hgoGQcA/HQwF5E
         K/MoG3ejW7+D3GwQNRWUnn/Yxp3rqST0poDv87Sd0aEUc800x1P4dIOlL+YyZqUf8txU
         oEGL1fgaSx4lPxD0hFj6bhTZN9CShTNCHiPxJxFXUKUHaLAHGfqiE98ILUKuomPm5EyE
         qUQbCbb0/YbUX7DlINouEP0xk/U6GQIN0RsBoyp+twlBj6yM2fqKBcpSa/nWaPqFdi56
         PPURydP/nVPbqfNBeMm3kLpOlo5Tf5bAEr1tG6MybVubc5UQu78uSg2s0354Nvng1Iuq
         03UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="l/hcCYqv";
       spf=pass (google.com: domain of 3rurqywykcesfheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3rurQYwYKCesfheRaOTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tNi6c24ibFtAn5AWfkDlI9d0bSXlCMxdJnW3OQAyW18=;
        b=FzpYBJ1cP/iAokkqhBZLh0ZORKLgTBdZ9XDo0Cvn8sdmJxeyNYz62lmA/ITi3JrpaF
         gnkD4DAyF8jy58oH4AfYzK/a0zXY0a8z9GsvpHVhz08YbDpHQIwThxYZA7TusyEJHaWH
         BvqhV1OLcE/f22rabT6F3a3Aa89/BpgpH+TSg/JXTzrZ2on+Vvbo4pRp/3ylDTw644Vw
         jCC/ORm17helpRQD9L7yozA08O84xauL6IO4yPimxGmKSFgtRH7MuLgLSzfUIu2O+9G1
         X/fIAHXMxw24KrCnDkNhy2NJO59m8pB6OWb0cJbzTuCArIj6bsPEiY5KB+FJl9wohabZ
         6RTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=tNi6c24ibFtAn5AWfkDlI9d0bSXlCMxdJnW3OQAyW18=;
        b=vJaLqUfPv6eseqBow0YvQR1bzBkLmyasfm5wsf9D4579RhXiMCqF4gSaH4btBVL45q
         Im/7uik3eU8tQYzx8lzsN7NgPGAXa/Qa6DQak2dXuUDD9awoWSzFoYp5oi6Nd5FnU7Ys
         oGA266sReb7UOWGFNU05NGXUmBenNEKLaTcumxiipyoy9cX4fUI6Vq/DTyHz0zf13Fhy
         eeuBC30GFBEPatQNXiycDTz5ru/xcl6qJWbwmJxWTkjzud1jIeKqyzmGjNGZMWt0as5o
         93SkyucTq7fJwYtN2GjWy1InVn3WcZIPbhbbGzWoiu25cJTKrsKLewTI/pH51qy1TKxP
         QUdw==
X-Gm-Message-State: AO0yUKVe4FCWAWlufGkfT3z1Qv8OdwvmlafFRawPYmozWhFSVESwafVD
	iMyIMO0UlMPmokq7SuoxoZo=
X-Google-Smtp-Source: AK7set8iaKpf294lOsxOcAcOevRG6iuwttRmBCzVgRJXlRt4s7ekR30PQKdGpJRQpL87azHkWKvuAA==
X-Received: by 2002:a17:90a:de8e:b0:22c:4e1:957 with SMTP id n14-20020a17090ade8e00b0022c04e10957mr395699pjv.152.1674635952064;
        Wed, 25 Jan 2023 00:39:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b406:b0:189:b2b2:56d5 with SMTP id
 x6-20020a170902b40600b00189b2b256d5ls18773464plr.0.-pod-prod-gmail; Wed, 25
 Jan 2023 00:39:11 -0800 (PST)
X-Received: by 2002:a17:90a:7804:b0:229:912:1340 with SMTP id w4-20020a17090a780400b0022909121340mr31920299pjk.39.1674635951368;
        Wed, 25 Jan 2023 00:39:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635951; cv=none;
        d=google.com; s=arc-20160816;
        b=nsBd0lwfODg1LIK98cpRG8ZQVUrJd1OjlTZZmXj6gfiHB+5WszEWAjIsuNGlC6uukT
         mMMquuALXj9MGiVNTKVueNAFX1PxBYjadKPbIkYKRPKuCibt1DscZcE9lt0pxOm/xfJy
         lTkC7+1a41w5sh1VnyBxtG+qQz4C3JQxLwcwPAMJ/yk2RdaTCZgZHS6Y+zQSRJm8Z95x
         ecqaT2MiyGKg5nL9u5WDqm5hru1BpWDBcc5GmxjO3LtvDAb+36cXmdhhvfnQD3duhgM2
         HO/hVVrrwXQ3WpaQ/0Ip/rw0bjZu5LSbtSskxh6b+GMPPYEYdH3RbS/3U2GsBRn8IBFq
         +5FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=J7ancMifNNyjJiTof8bzSGdh+LvtuOAZ/yhUxoIZ6EY=;
        b=XXEesJChhQbbhLM8Xzz7yrEw4bx3JlYjCCV5OtlsxrGkJE9optTtHd5zcUbwnMZuqo
         vqTsbp5zMrX1jEAmLGJ0M5phwt6L/S3s21SY423XYPs3zuEcWnTck+VkeWtHTu3J8Kbp
         R4ZCoEWArdYeTJkhvBb9oM+6JtVqF6I0CcAAt2Pwohmp1QbuSfL/+wxbiaoiqoz7Km7C
         BJVB/xqUxmRFWrgMhUTY975uuFj1OgBA2s6zKKDeixfNEHgy4vMz6zBMyYzkj9zj50Dm
         WjxewAXuP7cn9cdFcH4+/zrU1pJ1ljVuRzLqsSYzdCf+Ba/mLhFX4vXFLARbRituC8/j
         TqMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="l/hcCYqv";
       spf=pass (google.com: domain of 3rurqywykcesfheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3rurQYwYKCesfheRaOTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id w2-20020a17090a5e0200b0022981e2b4c9si83703pjf.1.2023.01.25.00.39.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:39:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rurqywykcesfheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id a62-20020a25ca41000000b0080b838a5199so3259806ybg.6
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:39:11 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:f7b0:20e8:ce66:f98])
 (user=surenb job=sendgmr) by 2002:a0d:ca88:0:b0:501:80db:3eca with SMTP id
 m130-20020a0dca88000000b0050180db3ecamr2010555ywd.100.1674635950405; Wed, 25
 Jan 2023 00:39:10 -0800 (PST)
Date: Wed, 25 Jan 2023 00:38:51 -0800
In-Reply-To: <20230125083851.27759-1-surenb@google.com>
Mime-Version: 1.0
References: <20230125083851.27759-1-surenb@google.com>
X-Mailer: git-send-email 2.39.1.405.gd4c25cc71f-goog
Message-ID: <20230125083851.27759-7-surenb@google.com>
Subject: [PATCH v2 6/6] mm: export dump_mm()
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: michel@lespinasse.org, jglisse@google.com, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, mgorman@techsingularity.net, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, peterz@infradead.org, 
	ldufour@linux.ibm.com, paulmck@kernel.org, luto@kernel.org, 
	songliubraving@fb.com, peterx@redhat.com, david@redhat.com, 
	dhowells@redhat.com, hughd@google.com, bigeasy@linutronix.de, 
	kent.overstreet@linux.dev, punit.agrawal@bytedance.com, lstoakes@gmail.com, 
	peterjung1337@gmail.com, rientjes@google.com, axelrasmussen@google.com, 
	joelaf@google.com, minchan@google.com, jannh@google.com, shakeelb@google.com, 
	tatashin@google.com, edumazet@google.com, gthelen@google.com, 
	gurua@google.com, arjunroy@google.com, soheil@google.com, 
	hughlynch@google.com, leewalsh@google.com, posk@google.com, will@kernel.org, 
	aneesh.kumar@linux.ibm.com, npiggin@gmail.com, chenhuacai@kernel.org, 
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	dave.hansen@linux.intel.com, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	johannes@sipsolutions.net, qianweili@huawei.com, wangzhou1@hisilicon.com, 
	herbert@gondor.apana.org.au, davem@davemloft.net, vkoul@kernel.org, 
	airlied@gmail.com, daniel@ffwll.ch, maarten.lankhorst@linux.intel.com, 
	mripard@kernel.org, tzimmermann@suse.de, l.stach@pengutronix.de, 
	krzysztof.kozlowski@linaro.org, patrik.r.jakobsson@gmail.com, 
	matthias.bgg@gmail.com, robdclark@gmail.com, quic_abhinavk@quicinc.com, 
	dmitry.baryshkov@linaro.org, tomba@kernel.org, hjc@rock-chips.com, 
	heiko@sntech.de, ray.huang@amd.com, kraxel@redhat.com, sre@kernel.org, 
	mcoquelin.stm32@gmail.com, alexandre.torgue@foss.st.com, tfiga@chromium.org, 
	m.szyprowski@samsung.com, mchehab@kernel.org, dimitri.sivanich@hpe.com, 
	zhangfei.gao@linaro.org, jejb@linux.ibm.com, martin.petersen@oracle.com, 
	dgilbert@interlog.com, hdegoede@redhat.com, mst@redhat.com, 
	jasowang@redhat.com, alex.williamson@redhat.com, deller@gmx.de, 
	jayalk@intworks.biz, viro@zeniv.linux.org.uk, nico@fluxnic.net, 
	xiang@kernel.org, chao@kernel.org, tytso@mit.edu, adilger.kernel@dilger.ca, 
	miklos@szeredi.hu, mike.kravetz@oracle.com, muchun.song@linux.dev, 
	bhe@redhat.com, andrii@kernel.org, yoshfuji@linux-ipv6.org, 
	dsahern@kernel.org, kuba@kernel.org, pabeni@redhat.com, perex@perex.cz, 
	tiwai@suse.com, haojian.zhuang@gmail.com, robert.jarzmik@free.fr, 
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
	linuxppc-dev@lists.ozlabs.org, x86@kernel.org, linux-kernel@vger.kernel.org, 
	linux-graphics-maintainer@vmware.com, linux-ia64@vger.kernel.org, 
	linux-arch@vger.kernel.org, loongarch@lists.linux.dev, kvm@vger.kernel.org, 
	linux-s390@vger.kernel.org, linux-sgx@vger.kernel.org, 
	linux-um@lists.infradead.org, linux-acpi@vger.kernel.org, 
	linux-crypto@vger.kernel.org, nvdimm@lists.linux.dev, 
	dmaengine@vger.kernel.org, amd-gfx@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, etnaviv@lists.freedesktop.org, 
	linux-samsung-soc@vger.kernel.org, intel-gfx@lists.freedesktop.org, 
	linux-mediatek@lists.infradead.org, linux-arm-msm@vger.kernel.org, 
	freedreno@lists.freedesktop.org, linux-rockchip@lists.infradead.org, 
	linux-tegra@vger.kernel.org, virtualization@lists.linux-foundation.org, 
	xen-devel@lists.xenproject.org, linux-stm32@st-md-mailman.stormreply.com, 
	linux-rdma@vger.kernel.org, linux-media@vger.kernel.org, 
	linux-accelerators@lists.ozlabs.org, sparclinux@vger.kernel.org, 
	linux-scsi@vger.kernel.org, linux-staging@lists.linux.dev, 
	target-devel@vger.kernel.org, linux-usb@vger.kernel.org, 
	netdev@vger.kernel.org, linux-fbdev@vger.kernel.org, linux-aio@kvack.org, 
	linux-fsdevel@vger.kernel.org, linux-erofs@lists.ozlabs.org, 
	linux-ext4@vger.kernel.org, devel@lists.orangefs.org, 
	kexec@lists.infradead.org, linux-xfs@vger.kernel.org, bpf@vger.kernel.org, 
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com, 
	selinux@vger.kernel.org, alsa-devel@alsa-project.org, kernel-team@android.com, 
	surenb@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="l/hcCYqv";       spf=pass
 (google.com: domain of 3rurqywykcesfheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3rurQYwYKCesfheRaOTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

mmap_assert_write_locked() is used in vm_flags modifiers. Because
mmap_assert_write_locked() uses dump_mm() and vm_flags are sometimes
modified from from inside a module, it's necessary to export
dump_mm() function.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 mm/debug.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/debug.c b/mm/debug.c
index 9d3d893dc7f4..96d594e16292 100644
--- a/mm/debug.c
+++ b/mm/debug.c
@@ -215,6 +215,7 @@ void dump_mm(const struct mm_struct *mm)
 		mm->def_flags, &mm->def_flags
 	);
 }
+EXPORT_SYMBOL(dump_mm);
 
 static bool page_init_poisoning __read_mostly = true;
 
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125083851.27759-7-surenb%40google.com.
