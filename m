Return-Path: <kasan-dev+bncBDPPVSUFVUPBBCX653CAMGQEXJBOL2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 70296B23BD5
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 00:24:25 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-b3f38d3cabesf4647417a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:24:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755037450; cv=pass;
        d=google.com; s=arc-20240605;
        b=Aqa0TGxoFHrCNeHgIMAaiv97BKz9r9NlSzeikYRLVsmJO3bXPwOfp9LsjnYYBiXKGB
         zZpAIRITRLoOHwCiRKr+qb8m37O/T06r5imHs/pQSBv1fCNdOEbmkiJl9acrphRxOEq1
         PRRjLF1M3muzYcs5L9Hz4yKKTDzhqDlKymvM4s6yxgSRKt3XSjxX3EMJZFD0EjrsMp3c
         GaB4E7IS3pBjWm2hBCprxSQvd62Cv67cArvNLxeSeKM0NA8sPiHbwm17ANlaPcfVSMBE
         muoO7MlqjRyBkQbVjySdUnDLYyQDJkv5YBcBl9je/ZryPKLJGA+8jQxsGR7VggS3Seow
         z9Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9aDsg52GrLrt/IzZrFTjTCPSUsyS5+fVI538w6H9V/w=;
        fh=TeIdYaLqG8dUcIyTjV/5PeMR9l3lKPI40XEcM1GQb1k=;
        b=CkIOUCAICVdoCyEf5/tzvIn5uNdIN3mo9M1ZEOqiTAN46JTlked9tU3z0cWY+7cnJ+
         q7J3oO+euYnKiLFxFeP27r5IdNA5hiGOTQyRkUnKMq7m0FMqZkw61+wk0Z1XDkUotg63
         dMbsGfxgEsxYplkvLUxcugjlEnUpPsEiz4w4oGhYsFW3ZGtNYI635jgdR84lkZX2ksYK
         4RWILe7kZjqPq18Fmot36+R+U/DxB+VoypU+Llr90GVSkhypQV8Nz5OaThrqwjQ2t9e4
         O/bEDOvgGdOTyVO0crVDmkbwpb1Z50ermvYc/EO4eRRSkmdw8DBfeg9KRPdxojny2hGH
         OpSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ApwVLuhz;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755037450; x=1755642250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9aDsg52GrLrt/IzZrFTjTCPSUsyS5+fVI538w6H9V/w=;
        b=fH0M2KelIDPRLuG9FSIQr111mGT+YRX5IR/+YN3Ew/AA5YAKFSdykmoCQgqPFdg5SM
         Vgfb41h5PtrVAYM1txuO1IbhBoHBEKTJXx7HWzRwYSyxdRApnNoUHUZ1kzoukWG8QGUS
         QrvI0wU9P6GsxNUjYsPMsZBUg1HTa8LUUxHJxDBgjPuHUoCXDn6Y1TSM8fk4CIKiSfTL
         1L31hCaT+iilLfte0zczBqLRwvKkMas+RUjMSbGrYUmNOOtSQiCPiRr6aJ+5ESTIgBn4
         ZEmstisf5WFGH6GLlVyPoDCtTLQIupNrL64J70C0Ihwv6lNsI3rbB5x6nbVn7+2WH9S3
         4OLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755037450; x=1755642250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9aDsg52GrLrt/IzZrFTjTCPSUsyS5+fVI538w6H9V/w=;
        b=B3L19MZt/dKEoO8WyF7KMJDsdmeAcXVhh4WadqFmNVf7JoJMUX+pfXROpQp2tR5I6z
         /jxivAgT5cR0KDWSb5TYnXTvUxLvlphuz1l+VZIggnnIWazvUfLucUCL133z62XNGewY
         RIg2Hp+oQgT9lCMSWqABoNyQ13hYjS6sAFKZ98cG1HCMo1OyMxpwCN6RNILantBIL1Ds
         hu5JimF5bYxcfWFmO0xq1a7RzjIQWmdpOqcSoThxT3M/s3g2yVg0gVDL7hQ3wCOKYGHk
         7hoNZAr5NH1eXcemBm0SGnvAu4hiJqS2rM6GP4f4uaa2QK1twpq/tOEo+HhsPSIRFKUc
         pi4w==
X-Forwarded-Encrypted: i=2; AJvYcCWx9Ksqj3CCab0hzCQDSSMQfKHapOFkj0Wm7erFlx+KZu68Y1Btnnm9Zh4l8LYf4bghhvQI4g==@lfdr.de
X-Gm-Message-State: AOJu0YwRod9I1YCEy/fAJG2S6PDCcXTVTD1n8T1sy1YGz9tlLSytoNwa
	mQ4Ga/kiG0opyeCKEGdvvhQB8IGcjsANDstx1tmf1epr/8IfjPr7ifuu
X-Google-Smtp-Source: AGHT+IERhNHsQJAvy7xDmY5W6Mt0R9w97AFFMQiFdyKvOFAsOZc0R1s5SVG3bEfuMhMaUBMHgGl43Q==
X-Received: by 2002:a17:903:2b0f:b0:243:3fe:4294 with SMTP id d9443c01a7336-2430d0a31f4mr13528805ad.12.1755037450371;
        Tue, 12 Aug 2025 15:24:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc6Xka8xuELN/+MrxejabdJFzbgm/yynTsRDwukJZPmdQ==
Received: by 2002:a17:903:4407:b0:240:b084:efd2 with SMTP id
 d9443c01a7336-242afb634c0ls65134985ad.0.-pod-prod-05-us; Tue, 12 Aug 2025
 15:24:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXeGyqIPOG19ZYQ6/euDhx/tqS7t54HDU/X53MiR1zBjkDnLb5lbGUiHzSY1Awk4kZA6ss0dsUKA4=@googlegroups.com
X-Received: by 2002:a17:902:e884:b0:234:c549:da0e with SMTP id d9443c01a7336-2430d20057cmr13661045ad.47.1755037449087;
        Tue, 12 Aug 2025 15:24:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755037449; cv=none;
        d=google.com; s=arc-20240605;
        b=J0NR1agiy7HV6+wSieKD73XryVWQu7hwY2YqEQGDWXcprpUnEaPXNIXx2VnvNnJmvP
         Agz4Mu/7j0f2WWUfUGC1Ovi9vRIi9CnB6aOvGi4z2KZReQlKhdU6atD4+aXw+BnsQ2e/
         ZnK0E8fjUAm9mp2g4tlZeNRowKp4o18OWVEhhtL7v34Zdw1qGAD5l2qoEoPHonaczqDr
         YLANSthJoTOWtzmU49mbPRHh7rVBJfpAr7fWzRIc57Fa/IUJ8jXAoAJ4DjT+yKFYEql4
         zUKxelCTBmrs06v/kA8SfaLDYdAvdRLin7MucVDwl1hYs5UCa98FbztNy0Atxt60/rTX
         B/6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gw0M5wI3UQLYJEOgNKt701AgY1nledSuuefZUpN8Q/g=;
        fh=Tio/B0c3twI8sUwB1hQk4NRezBKz6Nzk7HSYcIqpcDs=;
        b=YbADyueHZAyIN16Ezr/dYgRWbyr5xSLwP0ATwkFZhgEcS2xlO3yoq5lMTVPIUpKQ2K
         A49Wlk+cBu+a5RQT0SkuL4f/05P7rU+OWYPanLz04bO1q25gIs6jOKIJzmXUmBO/8g5s
         QI2lyU9UspHTLCwl1XkQ1nIjKrXTL7a5iQ+8W+tmtVjQ5pOeDvnF4IsSuGm0oANy0O3L
         boTrIIm0Qp8S5Y6fSd6oUI7xtUuFAL2QunPPICe2L0xp3ieyXy5OUdrwsw9dMVj2oK/y
         t6sjW3432MzXKKPLDolerusSwKleueJ1tkX0EXQ/RKo2TVwRQm60gAF2P8QVRUVVMSd1
         xnYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ApwVLuhz;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1fb2627si14380525ad.5.2025.08.12.15.24.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 15:24:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-7074710a809so52737946d6.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 15:24:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXioBKubmUsLOGQXOVJvRA6Tcq4adYgnBfILhstC+R2zkAEYVk+RXXLFT/AgP2anrs+zNOt3EtPnEE=@googlegroups.com
X-Gm-Gg: ASbGncsrcYvIMPCvQu/Y04iitl93pbgkv9QaTMqLYEOzo40Rs0he9OKVYosPClwwQwR
	y7dMWvZz1667qE13sL0pSYbFnu9Xh7LyPA1lXbQWax7FX3l0CcnlphmuOGyGfKaX4xyoRjMp8gN
	mUpPdDVgbzcDLvqhzv947vPXPiDDl6QZYv9kEnkjU6fksGLuvaVmG9HwCGXvd/53mxW+PtMoLmP
	uIM9w==
X-Received: by 2002:ad4:5e85:0:b0:707:4f43:eed6 with SMTP id
 6a1803df08f44-709e881f1f7mr11824886d6.19.1755037447536; Tue, 12 Aug 2025
 15:24:07 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-8-marievic@google.com>
In-Reply-To: <20250811221739.2694336-8-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Aug 2025 18:23:56 -0400
X-Gm-Features: Ac12FXwTra0WMZYWLdGULPxe1JGuotd8Jb883BcWC58YqpPZjgUY2pOTUgm9BrI
Message-ID: <CA+GJov5bDn4qgWXo=xwmrkQ6-cw8BizkG2h20sCRgaSmQhV6jw@mail.gmail.com>
Subject: Re: [PATCH v2 7/7] Documentation: kunit: Document new parameterized
 test features
To: Marie Zhussupova <marievic@google.com>
Cc: davidgow@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rmoar@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ApwVLuhz;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f29 as
 permitted sender) smtp.mailfrom=rmoar@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Rae Moar <rmoar@google.com>
Reply-To: Rae Moar <rmoar@google.com>
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

On Mon, Aug 11, 2025 at 6:18=E2=80=AFPM Marie Zhussupova <marievic@google.c=
om> wrote:
>
> This patch updates the KUnit docs to show how to use the new
> parameterized test context to share resources
> between parameter runs. It documents and show examples
> of different ways the test user can pass parameter
> arrays to a parameterized test. Finally, it specifies the
> parameterized testing terminology.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

Hello!

This mostly looks good to me. I would be happy for this to go in as
is. However, I do have comments about adding links below.

Reviewed-by: Rae Moar <rmoar@google.com>

Thanks!
-Rae

>
> Changes in v2:
>
> - The documentation was updated to establish the parameterized
>   testing terminology and reflect all the patch series changes.
> - The references to other parts of the KUnit Documentation were
>   not changed from being "Documentation/dev-tools/kunit/api/test.rst"
>   to ":ref:`kunit-resource`" links as originally planned. This is
>   because the existing way shows up as a link to a webpage and it
>   would be hard for people reading the documentation as an .rst
>   file to find the referred section without having the file path.
> - The code examples were made more concise.
> - Minor edits to titles and formatting.
>
> ---
>  Documentation/dev-tools/kunit/usage.rst | 342 +++++++++++++++++++++++-
>  1 file changed, 336 insertions(+), 6 deletions(-)
>
> diff --git a/Documentation/dev-tools/kunit/usage.rst b/Documentation/dev-=
tools/kunit/usage.rst
> index 066ecda1dd98..b236bb07aaca 100644
> --- a/Documentation/dev-tools/kunit/usage.rst
> +++ b/Documentation/dev-tools/kunit/usage.rst
> @@ -542,11 +542,29 @@ There is more boilerplate code involved, but it can=
:
>  Parameterized Testing
>  ~~~~~~~~~~~~~~~~~~~~~
>
> -The table-driven testing pattern is common enough that KUnit has special
> -support for it.
> -
> -By reusing the same ``cases`` array from above, we can write the test as=
 a
> -"parameterized test" with the following.
> +To run a test case against multiple inputs, KUnit provides a parameteriz=
ed
> +testing framework. This feature formalizes and extends the concept of
> +table-driven tests discussed previously. A KUnit test is determined to b=
e
> +parameterized if a parameter generator function is provided when registe=
ring
> +the test case.
> +
> +To establish the terminology, "parameterized test" refers to the group o=
f all
> +runs of a single test function with different parameters. "Parameter run=
" refers
> +to the execution of the test case function with a single parameter.
> +"Parameterized test context" is the ``struct kunit`` that holds the
> +context for the entire parameterized test. Finally, "parameter run conte=
xt" is
> +the ``struct kunit`` that holds the context of the individual parameter =
run.
> +
> +Passing Parameters to a Test
> +^^^^^^^^^^^^^^^^^^^^^^^^^^^^
> +There are three ways to provide the parameters to a test:
> +
> +Array Parameter Macros:
> +
> +   KUnit provides special support for the common table-driven testing pa=
ttern.
> +   By applying either ``KUNIT_ARRAY_PARAM`` or ``KUNIT_ARRAY_PARAM_DESC`=
` to the
> +   ``cases`` array from the previous section, we can create a parameteri=
zed test
> +   as shown below:
>
>  .. code-block:: c
>
> @@ -555,7 +573,7 @@ By reusing the same ``cases`` array from above, we ca=
n write the test as a
>                 const char *str;
>                 const char *sha1;
>         };
> -       const struct sha1_test_case cases[] =3D {
> +       static const struct sha1_test_case cases[] =3D {
>                 {
>                         .str =3D "hello world",
>                         .sha1 =3D "2aae6c35c94fcfb415dbe95f408b9ce91ee846=
ed",
> @@ -590,6 +608,318 @@ By reusing the same ``cases`` array from above, we =
can write the test as a
>                 {}
>         };
>
> +Custom Parameter Generator Function:
> +
> +   The generator function is responsible for generating parameters one-b=
y-one
> +   and has the following signature:
> +   ``const void* (*)(struct kunit *test, const void *prev, char *desc)``=
.
> +   You can pass the generator function to the ``KUNIT_CASE_PARAM``
> +   or ``KUNIT_CASE_PARAM_WITH_INIT`` macros.
> +
> +   The function receives the previously generated parameter as the ``pre=
v`` argument
> +   (which is ``NULL`` on the first call) and can also access the paramet=
erized
> +   test context passed as the ``test`` argument. KUnit calls this functi=
on
> +   repeatedly until it returns ``NULL``, which signifies that a paramete=
rized
> +   test ended.
> +
> +   Below is an example of how it works:
> +
> +.. code-block:: c
> +
> +       #define MAX_TEST_BUFFER_SIZE 8
> +
> +       // Example generator function. It produces a sequence of buffer s=
izes that
> +       // are powers of two, starting at 1 (e.g., 1, 2, 4, 8).
> +       static const void *buffer_size_gen_params(struct kunit *test, con=
st void *prev, char *desc)
> +       {
> +               long prev_buffer_size =3D (long)prev;
> +               long next_buffer_size =3D 1; // Start with an initial siz=
e of 1.
> +
> +               // Stop generating parameters if the limit is reached or =
exceeded.
> +               if (prev_buffer_size >=3D MAX_TEST_BUFFER_SIZE)
> +                       return NULL;
> +
> +               // For subsequent calls, calculate the next size by doubl=
ing the previous one.
> +               if (prev)
> +                       next_buffer_size =3D prev_buffer_size << 1;
> +
> +               return (void *)next_buffer_size;
> +       }
> +
> +       // Simple test to validate that kunit_kzalloc provides zeroed mem=
ory.
> +       static void buffer_zero_test(struct kunit *test)
> +       {
> +               long buffer_size =3D (long)test->param_value;
> +               // Use kunit_kzalloc to allocate a zero-initialized buffe=
r. This makes the
> +               // memory "parameter run managed," meaning it's automatic=
ally cleaned up at
> +               // the end of each parameter run.
> +               int *buf =3D kunit_kzalloc(test, buffer_size * sizeof(int=
), GFP_KERNEL);
> +
> +               // Ensure the allocation was successful.
> +               KUNIT_ASSERT_NOT_NULL(test, buf);
> +
> +               // Loop through the buffer and confirm every element is z=
ero.
> +               for (int i =3D 0; i < buffer_size; i++)
> +                       KUNIT_EXPECT_EQ(test, buf[i], 0);
> +       }
> +
> +       static struct kunit_case buffer_test_cases[] =3D {
> +               KUNIT_CASE_PARAM(buffer_zero_test, buffer_size_gen_params=
),
> +               {}
> +       };
> +
> +Runtime Parameter Array Registration in the Init Function:
> +
> +   For more complex scenarios, you can directly register a parameter arr=
ay
> +   to the parameterized test context.
> +
> +   To do this, you must pass the parameterized test context, the array i=
tself,
> +   the array size, and a ``get_description()`` function to the
> +   ``kunit_register_params_array()`` macro. This macro populates
> +   ``struct kunit_params`` within the parameterized test context, effect=
ively
> +   storing a parameter array object. The ``get_description()`` function =
will
> +   be used for populating parameter descriptions and has the following s=
ignature:
> +   ``void (*)(struct kunit *test, const void *param, char *desc)``. Note=
 that it
> +   also has access to the parameterized test context.
> +
> +      .. important::
> +         When using this way to register a parameter array, you will nee=
d to
> +         manually pass ``kunit_array_gen_params()`` as the generator fun=
ction to
> +         ``KUNIT_CASE_PARAM_WITH_INIT``. ``kunit_array_gen_params()`` is=
 a KUnit
> +         helper that will use the registered array to generate the param=
eters.
> +
> +        If needed, instead of passing the KUnit helper, you can also pas=
s your
> +        own custom generator function that utilizes the parameter array.=
 To
> +        access the parameter array from within the parameter generator
> +        function use ``test->params_array.params``.
> +
> +   The ``kunit_register_params_array()`` macro should be called within a
> +   ``param_init()`` function that initializes the parameterized test and=
 has
> +   the following signature ``int (*)(struct kunit *test)``. For a detail=
ed
> +   explanation of this mechanism please refer to the "Adding Shared Reso=
urces"
> +   section that is after this one. This method supports registering both
> +   dynamically built and static parameter arrays.
> +
> +   The code snippet below shows the ``example_param_init_dynamic_arr`` t=
est that
> +   utilizes ``make_fibonacci_params()`` to create a dynamic array, which=
 is then
> +   registered using ``kunit_register_params_array()``. To see the full c=
ode
> +   please refer to lib/kunit/kunit-example-test.c starting at line 396.

It would be great if this could be a bootlin link that takes you right
to this file at line 396. You can use external links with this
documentation: https://sublime-and-sphinx-guide.readthedocs.io/en/latest/re=
ferences.html.

> +
> +.. code-block:: c
> +
> +       /*
> +       * Example of a parameterized test param_init() function that regi=
sters a dynamic
> +       * array of parameters.
> +       */
> +       static int example_param_init_dynamic_arr(struct kunit *test)
> +       {
> +               size_t seq_size;
> +               int *fibonacci_params;
> +
> +               kunit_info(test, "initializing parameterized test\n");
> +
> +               seq_size =3D 6;
> +               fibonacci_params =3D make_fibonacci_params(test, seq_size=
);
> +               if (!fibonacci_params)
> +                       return -ENOMEM;
> +               /*
> +               * Passes the dynamic parameter array information to the p=
arameterized test
> +               * context struct kunit. The array and its metadata will b=
e stored in
> +               * test->parent->params_array. The array itself will be lo=
cated in
> +               * params_data.params.
> +               */
> +               kunit_register_params_array(test, fibonacci_params, seq_s=
ize,
> +                                       example_param_dynamic_arr_get_des=
c);
> +               return 0;
> +       }
> +
> +       static struct kunit_case example_test_cases[] =3D {
> +               /*
> +                * Note how we pass kunit_array_gen_params() to use the a=
rray we
> +                * registered in example_param_init_dynamic_arr() to gene=
rate
> +                * parameters.
> +                */
> +               KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_=
dynamic_arr,
> +                                          kunit_array_gen_params,
> +                                          example_param_init_dynamic_arr=
,
> +                                          example_param_exit_dynamic_arr=
),
> +               {}
> +       };
> +
> +Adding Shared Resources
> +^^^^^^^^^^^^^^^^^^^^^^^
> +All parameter runs in this framework hold a reference to the parameteriz=
ed test
> +context, which can be accessed using the parent ``struct kunit`` pointer=
. The
> +parameterized test context is not used to execute any test logic itself;=
 instead,
> +it serves as a container for shared resources.
> +
> +It's possible to add resources to share between parameter runs within a
> +parameterized test by using ``KUNIT_CASE_PARAM_WITH_INIT``, to which you=
 pass
> +custom ``param_init()`` and ``param_exit()`` functions. These functions =
run once
> +before and once after the parameterized test, respectively.
> +
> +The ``param_init()`` function, with the signature ``int (*)(struct kunit=
 *test)``,
> +can be used for adding resources to the ``resources`` or ``priv`` fields=
 of
> +the parameterized test context, registering the parameter array, and any=
 other
> +initialization logic.
> +
> +The ``param_exit()`` function, with the signature ``void (*)(struct kuni=
t *test)``,
> +can be used to release any resources that were not parameterized test ma=
naged (i.e.
> +not automatically cleaned up after the parameterized test ends) and for =
any other
> +exit logic.
> +
> +Both ``param_init()`` and ``param_exit()`` are passed the parameterized =
test
> +context behind the scenes. However, the test case function receives the =
parameter
> +run context. Therefore, to manage and access shared resources from withi=
n a test
> +case function, you must use ``test->parent``.
> +
> +For instance, finding a shared resource allocated by the Resource API re=
quires
> +passing ``test->parent`` to ``kunit_find_resource()``. This principle ex=
tends to
> +all other APIs that might be used in the test case function, including
> +``kunit_kzalloc()``, ``kunit_kmalloc_array()``, and others (see
> +Documentation/dev-tools/kunit/api/test.rst and the
> +Documentation/dev-tools/kunit/api/resource.rst).

It would be great if these references could be links to those pages in
the kernel docs.

> +
> +.. note::
> +   The ``suite->init()`` function, which executes before each parameter =
run,
> +   receives the parameter run context. Therefore, any resources set up i=
n
> +   ``suite->init()`` are cleaned up after each parameter run.
> +
> +The code below shows how you can add the shared resources. Note that thi=
s code
> +utilizes the Resource API, which you can read more about here:
> +Documentation/dev-tools/kunit/api/resource.rst. To see the full version =
of this
> +code please refer to lib/kunit/kunit-example-test.c starting at line 280=
.

Same here with the reference to this rst file and this file and line
number in the code.


> +
> +.. code-block:: c
> +
> +       static int example_resource_init(struct kunit_resource *res, void=
 *context)
> +       {
> +               ... /* Code that allocates memory and stores context in r=
es->data. */
> +       }
> +
> +       /* This function deallocates memory for the kunit_resource->data =
field. */
> +       static void example_resource_free(struct kunit_resource *res)
> +       {
> +               kfree(res->data);
> +       }
> +
> +       /* This match function locates a test resource based on defined c=
riteria. */
> +       static bool example_resource_alloc_match(struct kunit *test, stru=
ct kunit_resource *res,
> +                                                void *match_data)
> +       {
> +               return res->data && res->free =3D=3D example_resource_fre=
e;
> +       }
> +
> +       /* Function to initialize the parameterized test. */
> +       static int example_param_init(struct kunit *test)
> +       {
> +               int ctx =3D 3; /* Data to be stored. */
> +               void *data =3D kunit_alloc_resource(test, example_resourc=
e_init,
> +                                                 example_resource_free,
> +                                                 GFP_KERNEL, &ctx);
> +               if (!data)
> +                       return -ENOMEM;
> +               kunit_register_params_array(test, example_params_array,
> +                                           ARRAY_SIZE(example_params_arr=
ay));
> +               return 0;
> +       }
> +
> +       /* Example test that uses shared resources in test->resources. */
> +       static void example_params_test_with_init(struct kunit *test)
> +       {
> +               int threshold;
> +               const struct example_param *param =3D test->param_value;
> +               /*  Here we pass test->parent to access the parameterized=
 test context. */
> +               struct kunit_resource *res =3D kunit_find_resource(test->=
parent,
> +                                                                example_=
resource_alloc_match,
> +                                                                NULL);
> +
> +               threshold =3D *((int *)res->data);
> +               KUNIT_ASSERT_LE(test, param->value, threshold);
> +               kunit_put_resource(res);
> +       }
> +
> +       static struct kunit_case example_test_cases[] =3D {
> +               KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init,=
 kunit_array_gen_params,
> +                                          example_param_init, NULL),
> +               {}
> +       };
> +
> +As an alternative to using the KUnit Resource API for sharing resources,=
 you can
> +place them in ``test->parent->priv``. This serves as a more lightweight =
method
> +for resource storage, best for scenarios where complex resource manageme=
nt is
> +not required.
> +
> +As stated previously ``param_init()`` and ``param_exit()`` get the param=
eterized
> +test context. So, you can directly use ``test->priv`` within ``param_ini=
t/exit``
> +to manage shared resources. However, from within the test case function,=
 you must
> +navigate up to the parent ``struct kunit`` i.e. the parameterized test c=
ontext.
> +Therefore, you need to use ``test->parent->priv`` to access those same
> +resources.
> +
> +The resources placed in ``test->parent->priv`` will need to be allocated=
 in
> +memory to persist across the parameter runs. If memory is allocated usin=
g the
> +KUnit memory allocation APIs (described more in the "Allocating Memory" =
section
> +below), you won't need to worry about deallocation. The APIs will make t=
he memory
> +parameterized test 'managed', ensuring that it will automatically get cl=
eaned up
> +after the parameterized test concludes.
> +
> +The code below demonstrates example usage of the ``priv`` field for shar=
ed
> +resources:
> +
> +.. code-block:: c
> +
> +       static const struct example_param {
> +               int value;
> +       } example_params_array[] =3D {
> +               { .value =3D 3, },
> +               { .value =3D 2, },
> +               { .value =3D 1, },
> +               { .value =3D 0, },
> +       };
> +
> +       /* Initialize the parameterized test context. */
> +       static int example_param_init_priv(struct kunit *test)
> +       {
> +               int ctx =3D 3; /* Data to be stored. */
> +               int arr_size =3D ARRAY_SIZE(example_params_array);
> +
> +               /*
> +                * Allocate memory using kunit_kzalloc(). Since the `para=
m_init`
> +                * function receives the parameterized test context, this=
 memory
> +                * allocation will be scoped to the lifetime of the param=
eterized test.
> +                */
> +               test->priv =3D kunit_kzalloc(test, sizeof(int), GFP_KERNE=
L);
> +
> +               /* Assign the context value to test->priv.*/
> +               *((int *)test->priv) =3D ctx;
> +
> +               /* Register the parameter array. */
> +               kunit_register_params_array(test, example_params_array, a=
rr_size, NULL);
> +               return 0;
> +       }
> +
> +       static void example_params_test_with_init_priv(struct kunit *test=
)
> +       {
> +               int threshold;
> +               const struct example_param *param =3D test->param_value;
> +
> +               /* By design, test->parent will not be NULL. */
> +               KUNIT_ASSERT_NOT_NULL(test, test->parent);
> +
> +               /* Here we use test->parent->priv to access the shared re=
source. */
> +               threshold =3D *(int *)test->parent->priv;
> +
> +               KUNIT_ASSERT_LE(test, param->value, threshold);
> +       }
> +
> +       static struct kunit_case example_tests[] =3D {
> +               KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_=
priv,
> +                                          kunit_array_gen_params,
> +                                          example_param_init_priv, NULL)=
,
> +               {}
> +       };
> +
>  Allocating Memory
>  -----------------
>
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov5bDn4qgWXo%3DxwmrkQ6-cw8BizkG2h20sCRgaSmQhV6jw%40mail.gmail.com.
