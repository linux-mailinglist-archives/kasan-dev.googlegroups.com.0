Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2ERU6UAMGQEJTECMFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id BB8F67A68AA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Sep 2023 18:14:33 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-55e16833517sf7753716eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Sep 2023 09:14:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695140072; cv=pass;
        d=google.com; s=arc-20160816;
        b=oYr7qK7Loqlt+NItJTlKgGRXGNXIxC7ukZO3PaSjRZtzG4RHQb0jdgig1An4lLD+bI
         BaF3NwP1zRts4i2wSDVLcSJCK3PVpKIY8crD9H9V0nAxCvVCLsMfJZQh7ZLkjwrmlARJ
         c+0iqYDNOoZkkM3X8foYBjfqgcaCBPqYEhaBc5vXMoxlBnoxhoTCpDM3ZvTdz8fApehu
         SjNXlhkzGW0ODPwc6PDEK6vgufmPnxX8SaYSKmI9iwsdwoL26uBxl3IDbZITMwSvV+BH
         qXxWMaOGm+V1tpU4IQl2Px7jfrF8bCkFeroOnoNy35V54sDDAgGZQzK/+RdqvFAp5eFP
         FJ/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oTqzE8503+Eg73ExFkSAT1CSf2FcbtMwWsggZDyN1x0=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=EQcDw+mvDlod//Si0LT8cgaHqiFuu5sQPMvaCZL7vmbqT4gMGEcVIzdw18Qd7zzmNF
         BW7peLgFpyFTaPgi3sE+yoHVRmUXh8CXQFhVBph1MkI1J6cVzAamxBttC6ypMcjpBN+A
         DkOv0TIeKBoqtCpZjqg1u1W/6ZJbCJz7HCR10+5zmxA/4wAdGsHmiajYKEm/5YYoR9Wm
         GersahAcrHJVrSFDLojn60YZLn0aUIoWbUJztPMIbVHnwujnyyF/QW/TsEdKnHH3GJ33
         k6+vITpHRhZj1DHU0THf9ibypxTVZCnXEHn+LkcWZp0+CDMCNv47wD3r75G7zrP38MRB
         v9Hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vSU8CyKZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695140072; x=1695744872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oTqzE8503+Eg73ExFkSAT1CSf2FcbtMwWsggZDyN1x0=;
        b=UJQYklloaT9zhh5th0rLc5jrW9uELutabCmfU86CfGo9Ksx6qPbqFUN8ti2MrsmJZV
         qggscXBsaYA77FxxF7X1yJV25hohREybnkc3TccWBEPeYsBOHAc+TpHh4BUwcJqOk5NZ
         EP3PuGs0O82Pyw9KqDhpncWp32J1PfMLlQO6aGqAEhPJv8WzLFbRiSI7QwNlgIyq7YYY
         GvmCU+9Gs2r4w98YcEk6+BxRz/E0UYrDc7XtP5P+dBxvr7NIvBbPn+0dpXgBtoHDaePN
         vvxgOFsRU9mWGZFBiQGhtC/biZAMqSSMnIteeUZNY6F12xZkr9FOSjI44PglXz9VMdfD
         aLPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695140072; x=1695744872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oTqzE8503+Eg73ExFkSAT1CSf2FcbtMwWsggZDyN1x0=;
        b=aYr/xT2zdpvZxzB1oSQNzPseahIl8xaxwSpqFqI9c64NZbz99Vfy7xl6OxN1/5KA4Z
         sjZJuwXELjHo5Gis7EYVEPAQYwOmyhquU0EM3t7FIBv+2HQxaUCUtVO4GFg9JhNNkyZS
         oQlgxCr7H9BZvVqNxWV62CSLHBk+SYmJBuSc0B7ovDnFfyy/9Aem2iFy7GlfU0II//u/
         WNf73n7QGKQKGYcZh/V2Fb3cHlLTbysFwJNOgWf+29TVVidT8+QX9pmbHV/BCLDdPCDN
         1QMCYtVXjMULQ4qMA/iMGKcGNf4fWQCbO9UMW9TzZjt4aNHrIMVn+i345TyG+iAEo76F
         oF7Q==
X-Gm-Message-State: AOJu0Yw3/vxYx2DsbG9FpRo+FiDyWoHfm1YMjII03fAFr64wDpvNrW3s
	mu0pUFyz4iO5j6p1fs1nazc=
X-Google-Smtp-Source: AGHT+IHhE6SwcNJW/iGPHZej1KmSuKuo4tYitO6faoMT6Nx8AZ5KGPbl++Q9psRGWs499ZqFgChR8w==
X-Received: by 2002:a05:6870:5b8b:b0:1d5:cdf7:bda9 with SMTP id em11-20020a0568705b8b00b001d5cdf7bda9mr16084718oab.41.1695140072125;
        Tue, 19 Sep 2023 09:14:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:154:b0:1ba:7f7e:2b78 with SMTP id
 z20-20020a056871015400b001ba7f7e2b78ls1166173oab.2.-pod-prod-09-us; Tue, 19
 Sep 2023 09:14:31 -0700 (PDT)
X-Received: by 2002:a54:4793:0:b0:3a8:5207:1d88 with SMTP id o19-20020a544793000000b003a852071d88mr13881278oic.49.1695140071490;
        Tue, 19 Sep 2023 09:14:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695140071; cv=none;
        d=google.com; s=arc-20160816;
        b=Z+HLVNHA/j0PnDCbyYT+iN4ksn+MCctxJy8iXCCMCNdvNf/RJ5uRpk8X78xM7R10VS
         NpAGPD6/PJZvIw5ndsNBoT/65TFc9FwePEz6aMOuDGcofWCi/+B73y1x+eW8zm5bUwlK
         J306Tv7hIcpI228Nc/HBqzb4xYMVIq+WHWDSAGUY9eofCihGzVsAZmDRsJZKgcB/0dTp
         0tvRLhIf0/o72eK7nNc4k1ejcQPd1EpwgwZj3sKuM+ugfhG8L/vtS32qlcy7hj8uj+ll
         5RbgKNFz82f2rgWFLWREJx8FupdskLp+wEj+WDVFxNXwWwuuk3Inf33/2ncvH/+q6H/K
         Br8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wCIcJHAWFPOLBSbECabbg7duQStJvSvwou+mFA2mS48=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=DVeE1RN4BwSDsJFh+1y3bt2Ji19KmVHHrSwiJMqPEqxWOfmqhBIrXSTuLrO6kTL5i9
         5xhTX93BLz9d23wSoOa/8nUoEIBdR/6xG5PBjvSuvS3X6XsS+eKQ8kCzdR99lWW6VyZw
         FchvNXutUzVit5x6SU8I9EU7w9+JhLDI4E7syEWT6qu/PA/k9aW9VMVaSGx/ELm1T852
         etG9MGoHGdtaabZxa7DHuJPp5wibYYDsrYdcNPn55fWL+LMOKqjefj04IrFNyv0dlRNs
         6WMCbmpjTkXJQRtXS+5WZkyuCQhY6rPRbywZWx3vhGKYDAI1SAD4TH8KapRIQN7ErJCl
         a2Fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vSU8CyKZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id c14-20020a056830348e00b006b9f166fa6asi1477847otu.4.2023.09.19.09.14.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Sep 2023 09:14:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id ca18e2360f4ac-7927952ca67so202761039f.2
        for <kasan-dev@googlegroups.com>; Tue, 19 Sep 2023 09:14:31 -0700 (PDT)
X-Received: by 2002:a6b:7111:0:b0:790:f866:d717 with SMTP id
 q17-20020a6b7111000000b00790f866d717mr323374iog.10.1695140071037; Tue, 19 Sep
 2023 09:14:31 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <3a7056408e391ff0c66b5f50c460a7b9f796228f.1694625260.git.andreyknvl@google.com>
In-Reply-To: <3a7056408e391ff0c66b5f50c460a7b9f796228f.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Sep 2023 18:13:51 +0200
Message-ID: <CAG_fn=UchfGsWMYnYdatDrzr_k+E_55HKvHhMO0VeKvSKONJWw@mail.gmail.com>
Subject: Re: [PATCH v2 09/19] lib/stackdepot: store next pool pointer in new_pool
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vSU8CyKZ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Sep 13, 2023 at 7:15=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Instead of using the last pointer in stack_pools for storing the pointer
> to a new pool (which does not yet store any stack records), use a new
> new_pool variable.
>
> This a purely code readability change: it seems more logical to store
> the pointer to a pool with a special meaning in a dedicated variable.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUchfGsWMYnYdatDrzr_k%2BE_55HKvHhMO0VeKvSKONJWw%40mail.gm=
ail.com.
